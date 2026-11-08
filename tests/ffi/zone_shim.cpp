// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// Lean bindings for the zone, casync, pose and journal code. Each trial is deterministic in its
// seed; `plant` switches on the defect a property's control must catch.
#include <lean/lean.h>

#include "casync/casync.h"
#include "transport/transport.h"
#include "zone/journal.h"
#include "zone/pose.h"
#include "zone/zone.h"

#include <cmath>
#include <cstring>
#include <string>

using namespace fabric;

namespace {

uint32_t mix(uint32_t p_seed, uint32_t p_k) {
	uint64_t v = uint64_t(p_seed) * 2654435761ULL + uint64_t(p_k) * 40503ULL + 12345ULL;
	v ^= v >> 13;
	v *= 0x9E3779B97F4A7C15ULL;
	return uint32_t(v >> 32);
}

casync::Bytes data_for(uint32_t p_seed) {
	size_t n = size_t(mix(p_seed, 1) % (600 * 1024));
	casync::Bytes d(n);
	uint32_t x = mix(p_seed, 2) | 1u;
	uint32_t period = 500 + mix(p_seed, 3) % 5000;
	for (size_t i = 0; i < n; i++) {
		x = x * 1103515245u + 12345u;
		d[i] = uint8_t(x >> 24) & ((i % period) < period / 2 ? 0xFF : 0x0F);
	}
	return d;
}

bool no_drop_migration(int, int, int p_channel, uint64_t p_seq, void *p_user) {
	uint32_t seed = *static_cast<uint32_t *>(p_user);
	// Datagram channels lose packets; the migration and asset channels are reliable streams.
	return p_channel != CH_MIGRATION && p_channel != CH_ASSET && mix(seed, uint32_t(p_seq)) % 5 == 0;
}

lean_obj_res bytes_obj(const std::vector<uint8_t> &p_bytes) {
	lean_object *out = lean_alloc_sarray(1, p_bytes.size(), p_bytes.size());
	std::memcpy(lean_sarray_cptr(out), p_bytes.data(), p_bytes.size());
	return out;
}

std::vector<uint8_t> bytes_in(b_lean_obj_arg p_array) {
	const uint8_t *p = lean_sarray_cptr(p_array);
	return std::vector<uint8_t>(p, p + lean_sarray_size(p_array));
}

} // namespace

extern "C" {

// SHA-512/256 of a byte array, as its 32 bytes.
LEAN_EXPORT lean_obj_res fz_lean_sha512_256(b_lean_obj_arg p_data) {
	std::vector<uint8_t> d = bytes_in(p_data);
	casync::ChunkId id = casync::sha512_256(d.data(), d.size());
	return bytes_obj(std::vector<uint8_t>(id.begin(), id.end()));
}

// The zones of the two-zone trials: the players' zone and the worker's. Ids are set once, in the
// configs, and everything else (endpoints, hand-over targets) reads them from there.
static constexpr int PLAYERS_ZONE = 0;
static constexpr int WORKER_ZONE = 1;
// Entity id bases, per trial. Garments sit above the whole player range (PLAYER_ENTITY_BASE + a 16-bit
// player id), the journal and reopen trials below it.
static constexpr int PLAYER_ID_SPAN = 1 << 16;
static constexpr int HANDOVER_ID_BASE = 3000000;
static constexpr int PAYLOAD_ID_BASE = 3100000;
static constexpr int JOURNAL_ID_BASE = 5000;
static constexpr int REOPEN_ID_BASE = 7000;
static_assert(HANDOVER_ID_BASE >= Zone::PLAYER_ENTITY_BASE + PLAYER_ID_SPAN, "garment ids collide with players");
static_assert(PAYLOAD_ID_BASE >= Zone::PLAYER_ENTITY_BASE + PLAYER_ID_SPAN, "garment ids collide with players");
static_assert(JOURNAL_ID_BASE < Zone::PLAYER_ENTITY_BASE && REOPEN_ID_BASE < Zone::PLAYER_ENTITY_BASE, "ids collide with players");
// Ticks a two-zone trial runs, and how far in (in 1/100 m) a spawned garment sits: inside the scene.
static constexpr int TRIAL_TICKS = 90;
static constexpr int HANDOVER_TICK = 5; // the payload trial hands over on this tick
static constexpr double SPAWN_MARGIN = 1.0;
static constexpr int SPAWN_STEPS = int((zone::SIM_BOUND - 2.0 * SPAWN_MARGIN) * 100.0);
static constexpr double GARMENT_HEIGHT_MAX = 2.0;
static constexpr int HEIGHT_STEPS = int(GARMENT_HEIGHT_MAX * 100.0);

// Two zones on a lossy network hand one entity over. Returns worst owners (bits 0-1), a lost
// tick (bit 2), and the players' zone owning it at the end (bit 3).
LEAN_EXPORT uint32_t fz_lean_handover_trial(uint32_t p_seed, uint8_t p_plant) {
	LoopbackNet net;
	net.set_delay(1 + int(mix(p_seed, 10) % 4));
	uint32_t seed = p_seed;
	net.set_drop(&no_drop_migration, &seed);
	ZoneConfig c0;
	c0.zone_id = PLAYERS_ZONE;
	c0.zone_count = 2;
	c0.capacity = 32;
	ZoneConfig c1 = c0;
	c1.zone_id = WORKER_ZONE;
	c1.plant_double_handover = p_plant != 0;
	LoopbackNet::Endpoint &e0 = net.add(c0.zone_id);
	LoopbackNet::Endpoint &e1 = net.add(c1.zone_id);
	Zone players(c0, &e0);
	Zone worker(c1, &e1);
	FabricEntity g;
	g.global_id = HANDOVER_ID_BASE + int(mix(p_seed, 11) % 1000);
	g.cx = SPAWN_MARGIN + double(mix(p_seed, 12) % SPAWN_STEPS) / 100.0;
	g.cy = double(mix(p_seed, 13) % HEIGHT_STEPS) / 100.0;
	g.payload[0] = 5u << 24;
	worker.spawn(g);
	int handover_at = 2 + int(mix(p_seed, 14) % 40);
	int worst = 0;
	bool lost = false;
	for (int t = 0; t < TRIAL_TICKS; t++) {
		if (t == handover_at) {
			worker.handover(g.global_id, c0.zone_id);
		}
		players.tick();
		worker.tick();
		net.deliver();
		int owners = int(players.state_of(g.global_id) == Zone::OWNED) + int(worker.state_of(g.global_id) == Zone::OWNED);
		bool held = players.state_of(g.global_id) != Zone::ABSENT || worker.state_of(g.global_id) != Zone::ABSENT;
		worst = owners > worst ? owners : worst;
		lost = lost || !held;
	}
	bool done = players.state_of(g.global_id) == Zone::OWNED && worker.state_of(g.global_id) == Zone::ABSENT;
	return uint32_t(worst & 3) | (lost ? 4u : 0u) | (done ? 8u : 0u);
}

// A garment with a seed-chosen payload is handed from the worker zone to the players' zone. 1 when
// the players' zone owns it with the same 56 payload bytes, and a zone reopened from the players'
// journal holds them too. With `plant`, the worker sends the intent without the payload.
LEAN_EXPORT uint8_t fz_lean_handover_payload_trial(uint32_t p_seed, uint8_t p_plant) {
	LoopbackNet net;
	net.set_delay(1 + int(mix(p_seed, 300) % 4));
	uint32_t seed = p_seed;
	net.set_drop(&no_drop_migration, &seed);
	ZoneConfig c0;
	c0.zone_id = PLAYERS_ZONE;
	c0.zone_count = 2;
	c0.capacity = 32;
	ZoneConfig c1 = c0;
	c1.zone_id = WORKER_ZONE;
	c1.plant_intent_without_payload = p_plant != 0;
	LoopbackNet::Endpoint &e0 = net.add(c0.zone_id);
	LoopbackNet::Endpoint &e1 = net.add(c1.zone_id);
	LoopbackNet::Endpoint &e2 = net.add(c1.zone_id + 1); // the reopened zone's own endpoint
	Zone players(c0, &e0);
	Zone worker(c1, &e1);
	if (!players.open_journal({})) {
		return 0;
	}
	FabricEntity g;
	g.global_id = PAYLOAD_ID_BASE + int(mix(p_seed, 301) % 1000);
	g.cx = SPAWN_MARGIN + double(mix(p_seed, 302) % SPAWN_STEPS) / 100.0;
	for (int k = 0; k < 14; k++) {
		g.payload[k] = mix(p_seed, 310 + uint32_t(k)) | 1u;
	}
	worker.spawn(g);
	for (int t = 0; t < TRIAL_TICKS; t++) {
		if (t == HANDOVER_TICK) {
			worker.handover(g.global_id, c0.zone_id);
		}
		players.tick();
		worker.tick();
		net.deliver();
	}
	const FabricEntity *got = players.entity(g.global_id);
	if (players.state_of(g.global_id) != Zone::OWNED || got == nullptr ||
			std::memcmp(got->payload, g.payload, sizeof(g.payload)) != 0) {
		return 0;
	}
	ZoneConfig cr = c0;
	cr.zone_count = 1;
	Zone reopened(cr, &e2);
	if (!reopened.open_journal(players.journal().image())) {
		return 0;
	}
	const FabricEntity *back = reopened.entity(g.global_id);
	return (back != nullptr && std::memcmp(back->payload, g.payload, sizeof(g.payload)) == 0) ? 1 : 0;
}

// Stores seed-chosen data, fetches it over the loopback from another peer. With `plant`, one
// stored chunk is corrupted first. Returns 1 when the fetched bytes equal the data, 2 when the
// fetch failed on a chunk that does not match its id, 0 otherwise.
LEAN_EXPORT uint8_t fz_lean_fetch_trial(uint32_t p_seed, uint8_t p_plant) {
	casync::Bytes data = data_for(p_seed);
	casync::ChunkStore store;
	casync::Bytes index = store.put(data);
	std::vector<casync::CaibxChunk> table;
	std::string err;
	casync::parse_caibx(index, table, err);
	if (p_plant != 0 && !table.empty()) {
		const casync::CaibxChunk &victim = table[mix(p_seed, 20) % table.size()];
		casync::Bytes plain(data.begin() + long(victim.start), data.begin() + long(victim.start + victim.size));
		plain[mix(p_seed, 21) % plain.size()] ^= 0x5A;
		store.put_compressed(victim.id, casync::compress_chunk(plain.data(), plain.size()));
	}
	LoopbackNet net;
	LoopbackNet::Endpoint &server = net.add(1);
	LoopbackNet::Endpoint &client = net.add(2);
	casync::Fetch fetch;
	if (!fetch.begin(index, 1, err)) {
		return 0;
	}
	for (int r = 0; r < 64 && !fetch.poll(client); r++) {
		casync::serve(server, store);
		net.deliver();
	}
	if (fetch.failed()) {
		return fetch.get_error().find("does not match its id") != std::string::npos ? 2 : 0;
	}
	casync::Bytes got;
	return fetch.result(got) && got == data ? 1 : 0;
}

// Writes an index for seed-chosen chunks and parses it back; 1 when the table survives. With
// `plant`, items carry each chunk's start offset, as the ported upload_asset wrote them.
LEAN_EXPORT uint8_t fz_lean_caibx_trial(uint32_t p_seed, uint8_t p_plant) {
	std::vector<casync::CaibxChunk> chunks;
	uint64_t at = 0;
	uint32_t n = 1 + mix(p_seed, 30) % 12;
	for (uint32_t i = 0; i < n; i++) {
		casync::CaibxChunk c;
		for (int k = 0; k < casync::CHUNK_ID_BYTES; k++) {
			c.id[k] = uint8_t(mix(p_seed, 100 + i * 32 + uint32_t(k)));
		}
		c.start = at;
		c.size = 1 + mix(p_seed, 31 + i) % casync::CHUNK_MAX_BYTES;
		at += c.size;
		chunks.push_back(c);
	}
	casync::Bytes index = casync::write_caibx(chunks);
	if (p_plant != 0) {
		for (uint32_t i = 0; i < n; i++) {
			uint64_t start = chunks[i].start;
			std::memcpy(index.data() + 64 + i * 40, &start, 8);
		}
	}
	std::vector<casync::CaibxChunk> back;
	std::string err;
	if (!casync::parse_caibx(index, back, err) || back.size() != chunks.size()) {
		return 0;
	}
	for (size_t i = 0; i < chunks.size(); i++) {
		if (back[i].id != chunks[i].id || back[i].start != chunks[i].start || back[i].size != chunks[i].size) {
			return 0;
		}
	}
	return 1;
}

// A seed-chosen pose through encode and decode: the worst component error, or -1 when decode
// refuses. With `plant`, the packet loses its last byte.
LEAN_EXPORT double fz_lean_pose_trial(uint32_t p_seed, uint8_t p_plant) {
	pose::Pose p;
	p.player_id = mix(p_seed, 40);
	p.tick = mix(p_seed, 41);
	p.mask = (uint64_t(mix(p_seed, 42)) << 32 | mix(p_seed, 43)) & ((uint64_t(1) << pose::BONE_COUNT) - 1);
	for (int k = 0; k < 3; k++) {
		p.root[k] = double(int32_t(mix(p_seed, 44 + k))) / 1000.0;
	}
	for (int b = 0; b < pose::BONE_COUNT; b++) {
		double q[4];
		double n = 0.0;
		for (int k = 0; k < 4; k++) {
			q[k] = double(int32_t(mix(p_seed, 50 + b * 4 + k))) / 2147483648.0;
			n += q[k] * q[k];
		}
		n = std::sqrt(n) + 1e-12;
		for (int k = 0; k < 4; k++) {
			p.rot[b][k] = float(q[k] / n);
		}
	}
	std::vector<uint8_t> enc = pose::encode(p);
	if (p_plant != 0) {
		enc.pop_back();
	}
	pose::Pose back;
	if (!pose::decode(enc.data(), int(enc.size()), back)) {
		return -1.0;
	}
	double worst = 0.0;
	for (int k = 0; k < 3; k++) {
		worst = std::fmax(worst, std::fabs(back.root[k] - p.root[k]));
	}
	for (int b = 0; b < pose::BONE_COUNT; b++) {
		if (!((p.mask >> b) & 1u)) {
			continue;
		}
		double sign = p.rot[b][3] < 0.0f ? -1.0 : 1.0;
		for (int k = 0; k < 4; k++) {
			worst = std::fmax(worst, std::fabs(double(back.rot[b][k]) - sign * double(p.rot[b][k])));
		}
	}
	return worst;
}

// The bone index of a role name as avatar .fbx.meta files spell it, or -1.
LEAN_EXPORT uint32_t fz_lean_bone_index(b_lean_obj_arg p_name) {
	return uint32_t(pose::bone_index(lean_string_cstr(p_name)));
}

// A seed-chosen run of spawns, payload updates, despawns and snapshots, then a replay into a
// fresh zone from the flushed image. 1 when the replayed slots equal the live ones. With `plant`,
// the replay starts from the image flushed before the last mutation.
LEAN_EXPORT uint8_t fz_lean_journal_trial(uint32_t p_seed, uint8_t p_plant) {
	constexpr int CAP = 16;
	std::vector<EntitySlot> live(CAP);
	Journal j;
	if (!j.open({})) {
		return 0;
	}
	std::vector<uint8_t> before_last;
	int steps = 4 + int(mix(p_seed, 60) % 24);
	for (int s = 0; s < steps; s++) {
		before_last = j.image();
		uint32_t op = mix(p_seed, 61 + uint32_t(s)) % 4;
		int slot = int(mix(p_seed, 90 + uint32_t(s)) % CAP);
		if (op <= 1 && !live[slot].active) {
			live[slot] = EntitySlot();
			live[slot].active = true;
			live[slot].entity.global_id = JOURNAL_ID_BASE + s;
			live[slot].entity.cx = double(s);
			j.spawn(slot, live[slot].entity);
		} else if (op == 1 || (op == 2 && live[slot].active)) {
			if (live[slot].active) {
				live[slot].entity.payload[3] = mix(p_seed, 120 + uint32_t(s));
				j.payload_update(slot, live[slot].entity);
			} else {
				j.snapshot(CAP, live.data());
			}
		} else if (op == 3 && live[slot].active) {
			j.despawn(slot, live[slot].entity.global_id);
			live[slot].active = false;
		} else {
			j.snapshot(CAP, live.data());
		}
	}
	Journal r;
	if (!r.open(p_plant != 0 ? before_last : j.image())) {
		return 0;
	}
	std::vector<EntitySlot> back(CAP);
	int count = 0;
	r.replay(CAP, back.data(), count);
	for (int i = 0; i < CAP; i++) {
		if (back[i].active != live[i].active) {
			return 0;
		}
		if (live[i].active && (back[i].entity.global_id != live[i].entity.global_id ||
									   std::memcmp(back[i].entity.payload, live[i].entity.payload, 56) != 0)) {
			return 0;
		}
	}
	return 1;
}

// A zone spawns, updates payloads and despawns through its own API, then a second zone reopens
// from the first one's journal image. 1 when the reopened zone holds the same entities and
// payloads. With `plant`, the second zone only opens the journal and skips the replay, which is
// what zone_journal_open did before.
LEAN_EXPORT uint8_t fz_lean_zone_reopen_trial(uint32_t p_seed, uint8_t p_plant) {
	LoopbackNet net;
	ZoneConfig c;
	c.zone_id = PLAYERS_ZONE;
	c.zone_count = 1;
	c.capacity = 16;
	LoopbackNet::Endpoint &ea = net.add(c.zone_id);
	LoopbackNet::Endpoint &eb = net.add(c.zone_id + 1); // the second zone's own endpoint
	Zone a(c, &ea);
	if (!a.open_journal({})) {
		return 0;
	}
	std::vector<int> ids;
	int n = 2 + int(mix(p_seed, 200) % 6);
	for (int k = 0; k < n; k++) {
		FabricEntity e;
		e.global_id = REOPEN_ID_BASE + k;
		e.payload[0] = mix(p_seed, 210 + uint32_t(k));
		if (a.spawn(e) < 0) {
			return 0;
		}
		ids.push_back(e.global_id);
	}
	uint32_t p[14] = {};
	p[13] = mix(p_seed, 230);
	a.set_payload(ids[0], p);
	a.despawn(ids[n - 1]);
	Zone b(c, &eb);
	if (p_plant != 0) {
		if (!b.journal().open(a.journal().image())) {
			return 0;
		}
	} else if (!b.open_journal(a.journal().image())) {
		return 0;
	}
	if (b.get_entity_count() != a.get_entity_count()) {
		return 0;
	}
	for (int id : ids) {
		const FabricEntity *x = a.entity(id);
		const FabricEntity *y = b.entity(id);
		if ((x == nullptr) != (y == nullptr)) {
			return 0;
		}
		if (x != nullptr && std::memcmp(x->payload, y->payload, 56) != 0) {
			return 0;
		}
	}
	return 1;
}

// Two players send poses to one zone; 1 when each receives the other's, root exact. With `plant`,
// player 1 claims player 2's id, which the zone must refuse.
LEAN_EXPORT uint8_t fz_lean_pose_relay_trial(uint32_t p_seed, uint8_t p_plant) {
	LoopbackNet net;
	ZoneConfig c;
	LoopbackNet::Endpoint &z = net.add(c.zone_id);
	LoopbackNet::Endpoint &pa = net.add(c.player_peer_base + 1);
	LoopbackNet::Endpoint &pb = net.add(c.player_peer_base + 2);
	c.zone_count = 1;
	c.capacity = 16;
	Zone zone(c, &z);
	pose::Pose poses[2];
	for (int k = 0; k < 2; k++) {
		poses[k].player_id = uint32_t(k + 1);
		poses[k].mask = (uint64_t(1) << pose::BONE_COUNT) - 1;
		for (int d = 0; d < 3; d++) {
			poses[k].root[d] = double(int32_t(mix(p_seed, 200 + uint32_t(k * 3 + d)))) / 1.0e6;
		}
	}
	if (p_plant != 0) {
		poses[0].player_id = 2;
	}
	bool a_sees_b = false;
	bool b_sees_a = false;
	LoopbackNet::Endpoint *ends[2] = { &pa, &pb };
	for (int t = 0; t < 8; t++) {
		for (int k = 0; k < 2; k++) {
			std::vector<uint8_t> enc = pose::encode(poses[k]);
			ends[k]->send(c.zone_id, CH_PLAYER, enc.data(), int(enc.size()));
		}
		zone.tick();
		net.deliver();
		for (int k = 0; k < 2; k++) {
			for (const Packet &p : ends[k]->drain(CH_PLAYER)) {
				pose::Pose got;
				if (!pose::decode(p.bytes.data(), int(p.bytes.size()), got)) {
					continue;
				}
				int other = 1 - k;
				bool match = got.player_id == uint32_t(other + 1) && got.root[0] == poses[other].root[0] &&
						got.root[1] == poses[other].root[1] && got.root[2] == poses[other].root[2];
				if (match && k == 0) {
					a_sees_b = true;
				} else if (match && k == 1) {
					b_sees_a = true;
				}
			}
		}
	}
	return a_sees_b && b_sees_a ? 1 : 0;
}

// A player moving at a steady speed (m/tick) must leave the zone holding that velocity, so its ghost
// box follows its motion rather than the acceleration floor. 1 when the held velocity matches the
// motion. With `plant` the player stays put, so the zone holds zero: the defect the fix removed.
// The held velocity is derived in doubles from the poses; this is rounding, not slack.
static constexpr double VELOCITY_TOLERANCE = 1.0e-9;
LEAN_EXPORT uint8_t fz_lean_player_motion_trial(uint32_t p_seed, uint8_t p_plant) {
	LoopbackNet net;
	ZoneConfig c;
	LoopbackNet::Endpoint &z = net.add(c.zone_id);
	LoopbackNet::Endpoint &pl = net.add(c.player_peer_base + 1);
	c.zone_count = 1;
	c.capacity = 16;
	Zone zone(c, &z);
	// 2% to 80% of V_MAX per tick on the longest axis, so no axis reaches the clamp.
	const double speed = (0.02 + 0.78 * double(mix(p_seed, 300) % 1000) / 1000.0) * zone::V_MAX;
	const double dir[3] = { 1.0, -0.5, 0.25 };
	pose::Pose ps;
	ps.player_id = 1;
	ps.mask = (uint64_t(1) << pose::BONE_COUNT) - 1;
	for (int t = 0; t < 8; t++) {
		for (int d = 0; d < 3; d++) {
			ps.root[d] = p_plant != 0 ? 0.0 : dir[d] * speed * double(t);
		}
		std::vector<uint8_t> enc = pose::encode(ps);
		pl.send(c.zone_id, CH_PLAYER, enc.data(), int(enc.size()));
		zone.tick();
		net.deliver();
	}
	const FabricEntity *e = zone.entity(Zone::PLAYER_ENTITY_BASE + 1);
	if (e == nullptr) {
		return 0;
	}
	for (int d = 0; d < 3; d++) {
		double got = d == 0 ? e->vx : (d == 1 ? e->vy : e->vz);
		if (std::fabs(got - dir[d] * speed) > VELOCITY_TOLERANCE) {
			return 0;
		}
	}
	return 1;
}
} // extern "C"
