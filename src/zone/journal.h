// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// FabricZoneJournal from entities-godot's multiplayer_fabric, on SQLite's in-memory database:
// every write serializes the database and hands the bytes to a flush callback (zone.elf keeps the
// newest image for the host to take), and replay starts from bytes the host hands back.
#pragma once

#include "zone_types.h"

#include <cstdint>
#include <vector>

struct sqlite3;

namespace fabric {

class Journal {
public:
	using FlushFn = void (*)(const uint8_t *p_data, uint64_t p_size, void *p_user);

	Journal() = default;
	~Journal();
	Journal(const Journal &) = delete;
	Journal &operator=(const Journal &) = delete;

	// An empty image makes a new journal; otherwise it is a previous flush.
	bool open(const std::vector<uint8_t> &p_image);
	void close();
	bool is_open() const { return db != nullptr; }
	void set_flush(FlushFn p_fn, void *p_user) {
		flush_fn = p_fn;
		flush_user = p_user;
	}
	void set_now(int64_t p_now) { now = p_now; }

	void spawn(int p_slot, const FabricEntity &p_entity);
	void despawn(int p_slot, int p_global_id);
	void payload_update(int p_slot, const FabricEntity &p_entity);
	void snapshot(int p_capacity, const EntitySlot *p_slots);
	bool replay(int p_capacity, EntitySlot *p_slots, int &r_entity_count);

	std::vector<uint8_t> image() const;
	uint64_t flushes() const { return flush_count; }

private:
	sqlite3 *db = nullptr;
	FlushFn flush_fn = nullptr;
	void *flush_user = nullptr;
	int64_t now = 0;
	uint64_t flush_count = 0;

	void exec(const char *p_sql);
	void flush();
	void mutation(const char *p_op, int p_slot, int p_global_id, const FabricEntity *p_entity);
};

} // namespace fabric
