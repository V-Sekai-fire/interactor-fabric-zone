// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "journal.h"

#include <sqlite3.h>

#include <cstring>

namespace fabric {

namespace {

constexpr int ENTITY_BYTES = 96;
constexpr int SLOT_RECORD = 4 + ENTITY_BYTES;

void pack_entity(const FabricEntity &p_e, uint8_t *p_out) {
	float tmp[9] = { float(p_e.cx), float(p_e.cy), float(p_e.cz), float(p_e.vx), float(p_e.vy), float(p_e.vz),
		float(p_e.ax), float(p_e.ay), float(p_e.az) };
	std::memcpy(p_out, tmp, 36);
	int32_t gid = p_e.global_id;
	std::memcpy(p_out + 36, &gid, 4);
	std::memcpy(p_out + 40, p_e.payload, 56);
}

void unpack_entity(const uint8_t *p_in, FabricEntity &r_e) {
	float tmp[9];
	std::memcpy(tmp, p_in, 36);
	r_e.cx = tmp[0];
	r_e.cy = tmp[1];
	r_e.cz = tmp[2];
	r_e.vx = tmp[3];
	r_e.vy = tmp[4];
	r_e.vz = tmp[5];
	r_e.ax = tmp[6];
	r_e.ay = tmp[7];
	r_e.az = tmp[8];
	int32_t gid;
	std::memcpy(&gid, p_in + 36, 4);
	r_e.global_id = gid;
	std::memcpy(r_e.payload, p_in + 40, 56);
}

const char *const SCHEMA = R"sql(
	CREATE TABLE IF NOT EXISTS entity_mutations (
		seq       INTEGER PRIMARY KEY AUTOINCREMENT,
		op        TEXT    NOT NULL,
		slot_idx  INTEGER NOT NULL,
		global_id INTEGER NOT NULL,
		entity    BLOB,
		ts        INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS entity_snapshots (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		last_mutation_seq INTEGER NOT NULL,
		slot_data         BLOB    NOT NULL,
		slot_count        INTEGER NOT NULL,
		ts                INTEGER NOT NULL
	);
)sql";

} // namespace

Journal::~Journal() {
	close();
}

bool Journal::open(const std::vector<uint8_t> &p_image) {
	close();
	if (sqlite3_open_v2("file:/fabric_zone_journal?vfs=memdb", &db,
				SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, nullptr) != SQLITE_OK) {
		close();
		return false;
	}
	if (!p_image.empty()) {
		unsigned char *copy = static_cast<unsigned char *>(sqlite3_malloc64(p_image.size()));
		if (copy == nullptr) {
			close();
			return false;
		}
		std::memcpy(copy, p_image.data(), p_image.size());
		if (sqlite3_deserialize(db, "main", copy, sqlite3_int64(p_image.size()), sqlite3_int64(p_image.size()),
					SQLITE_DESERIALIZE_FREEONCLOSE | SQLITE_DESERIALIZE_RESIZEABLE) != SQLITE_OK) {
			close();
			return false;
		}
	}
	exec("PRAGMA journal_mode=MEMORY");
	exec(SCHEMA);
	return true;
}

void Journal::close() {
	if (db != nullptr) {
		sqlite3_close(db);
		db = nullptr;
	}
}

void Journal::exec(const char *p_sql) {
	char *err = nullptr;
	if (sqlite3_exec(db, p_sql, nullptr, nullptr, &err) != SQLITE_OK) {
		sqlite3_free(err);
	}
}

std::vector<uint8_t> Journal::image() const {
	std::vector<uint8_t> out;
	if (db == nullptr) {
		return out;
	}
	sqlite3_int64 size = 0;
	unsigned char *bytes = sqlite3_serialize(db, "main", &size, 0);
	if (bytes != nullptr) {
		out.assign(bytes, bytes + size);
		sqlite3_free(bytes);
	}
	return out;
}

void Journal::flush() {
	flush_count++;
	if (flush_fn != nullptr) {
		std::vector<uint8_t> bytes = image();
		flush_fn(bytes.data(), bytes.size(), flush_user);
	}
}

void Journal::mutation(const char *p_op, int p_slot, int p_global_id, const FabricEntity *p_entity) {
	if (db == nullptr) {
		return;
	}
	sqlite3_stmt *stmt = nullptr;
	sqlite3_prepare_v2(db, "INSERT INTO entity_mutations(op,slot_idx,global_id,entity,ts) VALUES(?,?,?,?,?)", -1,
			&stmt, nullptr);
	uint8_t buf[ENTITY_BYTES];
	sqlite3_bind_text(stmt, 1, p_op, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, p_slot);
	sqlite3_bind_int(stmt, 3, p_global_id);
	if (p_entity != nullptr) {
		pack_entity(*p_entity, buf);
		sqlite3_bind_blob(stmt, 4, buf, ENTITY_BYTES, SQLITE_TRANSIENT);
	} else {
		sqlite3_bind_null(stmt, 4);
	}
	sqlite3_bind_int64(stmt, 5, now);
	sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	flush();
}

void Journal::spawn(int p_slot, const FabricEntity &p_entity) {
	mutation("spawn", p_slot, p_entity.global_id, &p_entity);
}

void Journal::despawn(int p_slot, int p_global_id) {
	mutation("despawn", p_slot, p_global_id, nullptr);
}

void Journal::payload_update(int p_slot, const FabricEntity &p_entity) {
	mutation("payload_update", p_slot, p_entity.global_id, &p_entity);
}

void Journal::snapshot(int p_capacity, const EntitySlot *p_slots) {
	if (db == nullptr) {
		return;
	}
	std::vector<uint8_t> buf;
	int active = 0;
	for (int i = 0; i < p_capacity; i++) {
		if (!p_slots[i].active) {
			continue;
		}
		uint8_t rec[SLOT_RECORD];
		uint32_t idx = uint32_t(i);
		std::memcpy(rec, &idx, 4);
		pack_entity(p_slots[i].entity, rec + 4);
		buf.insert(buf.end(), rec, rec + SLOT_RECORD);
		active++;
	}
	int64_t last_seq = 0;
	sqlite3_stmt *st = nullptr;
	sqlite3_prepare_v2(db, "SELECT MAX(seq) FROM entity_mutations", -1, &st, nullptr);
	if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL) {
		last_seq = sqlite3_column_int64(st, 0);
	}
	sqlite3_finalize(st);
	sqlite3_stmt *stmt = nullptr;
	sqlite3_prepare_v2(db, "INSERT INTO entity_snapshots(last_mutation_seq,slot_data,slot_count,ts) VALUES(?,?,?,?)",
			-1, &stmt, nullptr);
	sqlite3_bind_int64(stmt, 1, last_seq);
	// An empty buffer binds as a zero-length blob: a null pointer would bind NULL, fail the
	// NOT NULL constraint, and the prune below would then drop mutations no snapshot holds.
	if (buf.empty()) {
		sqlite3_bind_zeroblob(stmt, 2, 0);
	} else {
		sqlite3_bind_blob(stmt, 2, buf.data(), int(buf.size()), SQLITE_TRANSIENT);
	}
	sqlite3_bind_int(stmt, 3, active);
	sqlite3_bind_int64(stmt, 4, now);
	bool stored = sqlite3_step(stmt) == SQLITE_DONE;
	sqlite3_finalize(stmt);
	if (stored && last_seq > 0) {
		sqlite3_stmt *prune = nullptr;
		sqlite3_prepare_v2(db, "DELETE FROM entity_mutations WHERE seq <= ?", -1, &prune, nullptr);
		sqlite3_bind_int64(prune, 1, last_seq);
		sqlite3_step(prune);
		sqlite3_finalize(prune);
	}
	flush();
}

bool Journal::replay(int p_capacity, EntitySlot *p_slots, int &r_entity_count) {
	if (db == nullptr) {
		return false;
	}
	r_entity_count = 0;
	bool any = false;
	int64_t after = -1;
	sqlite3_stmt *snap = nullptr;
	if (sqlite3_prepare_v2(db,
				"SELECT last_mutation_seq, slot_data, slot_count FROM entity_snapshots ORDER BY id DESC LIMIT 1", -1,
				&snap, nullptr) == SQLITE_OK &&
			sqlite3_step(snap) == SQLITE_ROW) {
		after = sqlite3_column_int64(snap, 0);
		int count = sqlite3_column_int(snap, 2);
		const uint8_t *blob = static_cast<const uint8_t *>(sqlite3_column_blob(snap, 1));
		int bytes = sqlite3_column_bytes(snap, 1);
		if (blob != nullptr && bytes == count * SLOT_RECORD) {
			for (int i = 0; i < count; i++) {
				const uint8_t *rec = blob + i * SLOT_RECORD;
				uint32_t slot;
				std::memcpy(&slot, rec, 4);
				if (int(slot) >= p_capacity) {
					continue;
				}
				p_slots[slot] = EntitySlot();
				p_slots[slot].active = true;
				unpack_entity(rec + 4, p_slots[slot].entity);
				r_entity_count++;
			}
			any = count > 0;
		}
	}
	sqlite3_finalize(snap);
	sqlite3_stmt *stmt = nullptr;
	if (sqlite3_prepare_v2(db, "SELECT op, slot_idx, global_id, entity FROM entity_mutations WHERE seq > ? ORDER BY seq ASC",
				-1, &stmt, nullptr) != SQLITE_OK) {
		return any;
	}
	sqlite3_bind_int64(stmt, 1, after);
	while (sqlite3_step(stmt) == SQLITE_ROW) {
		const char *op = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
		int slot = sqlite3_column_int(stmt, 1);
		int gid = sqlite3_column_int(stmt, 2);
		if (slot < 0 || slot >= p_capacity || op == nullptr) {
			continue;
		}
		if (std::strcmp(op, "spawn") == 0 || std::strcmp(op, "payload_update") == 0) {
			const uint8_t *blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmt, 3));
			if (blob != nullptr && sqlite3_column_bytes(stmt, 3) == ENTITY_BYTES) {
				if (!p_slots[slot].active) {
					p_slots[slot] = EntitySlot();
					p_slots[slot].active = true;
					unpack_entity(blob, p_slots[slot].entity);
					r_entity_count++;
					any = true;
				} else if (p_slots[slot].entity.global_id == gid) {
					unpack_entity(blob, p_slots[slot].entity);
					any = true;
				}
			}
		} else if (std::strcmp(op, "despawn") == 0) {
			if (p_slots[slot].active && p_slots[slot].entity.global_id == gid) {
				p_slots[slot].active = false;
				r_entity_count--;
				any = true;
			}
		}
	}
	sqlite3_finalize(stmt);
	if (r_entity_count < 0) {
		r_entity_count = 0;
	}
	return any;
}

} // namespace fabric
