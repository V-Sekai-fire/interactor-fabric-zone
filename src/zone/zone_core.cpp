// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "zone_core.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace fabric::zone {

namespace {

R128 r128_from_real_um(real_t p_v) {
	return r128_from_float(float(p_v * 1000000.0));
}

real_t r128_to_real_m(R128 p_v) {
	return real_t(int64_t(p_v.hi)) * real_t(0.000001);
}

int64_t r128_to_coord(R128 p_v) {
	return int64_t(r128ToInt(&p_v));
}

uint32_t snap_delta(real_t p_v, real_t p_ah) {
	return per_entity_delta_poly(r128_from_real_um(p_v), r128_from_real_um(p_ah));
}

} // namespace

Bytes pack_intent(int p_eid, int p_to, uint32_t p_arrival, const FabricEntity &p_entity) {
	Bytes b(INTENT_SIZE);
	uint64_t eid64 = uint64_t(p_eid);
	uint32_t to32 = uint32_t(p_to);
	std::memcpy(b.data() + 0, &eid64, 8);
	std::memcpy(b.data() + 8, &to32, 4);
	std::memcpy(b.data() + 12, &p_arrival, 4);
	double vals[9] = { p_entity.cx, p_entity.cy, p_entity.cz, p_entity.vx, p_entity.vy, p_entity.vz, p_entity.ax,
		p_entity.ay, p_entity.az };
	for (int i = 0; i < 9; i++) {
		std::memcpy(b.data() + 16 + i * 8, &vals[i], 8);
	}
	return b;
}

bool unpack_intent(const uint8_t *p_data, int p_size, int &r_eid, int &r_to, uint32_t &r_arrival,
		FabricEntity &r_entity) {
	if (p_size < INTENT_SIZE) {
		return false;
	}
	uint64_t eid64;
	uint32_t to32;
	std::memcpy(&eid64, p_data + 0, 8);
	std::memcpy(&to32, p_data + 8, 4);
	std::memcpy(&r_arrival, p_data + 12, 4);
	r_eid = int(eid64);
	r_to = int(to32);
	double vals[9];
	for (int i = 0; i < 9; i++) {
		std::memcpy(&vals[i], p_data + 16 + i * 8, 8);
	}
	r_entity.cx = vals[0];
	r_entity.cy = vals[1];
	r_entity.cz = vals[2];
	r_entity.vx = vals[3];
	r_entity.vy = vals[4];
	r_entity.vz = vals[5];
	r_entity.ax = vals[6];
	r_entity.ay = vals[7];
	r_entity.az = vals[8];
	r_entity.global_id = int(eid64);
	return true;
}

uint32_t staging_timeout(uint32_t p_srtt, uint32_t p_rttvar, bool p_rtt_measured, uint32_t p_hz) {
	if (!p_rtt_measured) {
		return p_hz;
	}
	uint32_t rto = p_srtt + 4 * p_rttvar;
	return rto < 1 ? 1 : rto;
}

Aabb scene_aabb() {
	return aabb_from_floats(float(-SIM_BOUND), float(SIM_BOUND), float(-SIM_BOUND), float(SIM_BOUND),
			float(-SIM_BOUND), float(SIM_BOUND));
}

uint32_t entity_hilbert(const FabricEntity &p_entity) {
	Aabb b = aabb_from_floats(float(p_entity.cx), float(p_entity.cx), float(p_entity.cy), float(p_entity.cy),
			float(p_entity.cz), float(p_entity.cz));
	Aabb scene = scene_aabb();
	return hilbert_of_aabb(&b, &scene);
}

GhostSnap make_ghost_snap(const FabricEntity &p_entity) {
	real_t ahx = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.ax));
	real_t ahy = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.ay));
	real_t ahz = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.az));
	real_t v = std::max(std::max(std::fabs(p_entity.vx), std::fabs(p_entity.vy)), std::fabs(p_entity.vz));
	real_t ah = std::max(std::max(ahx, ahy), ahz);
	uint32_t d = snap_delta(v, ah);
	R128 dk = r128_from_u32(d);
	R128 gex = ghost_bound(r128_from_real_um(std::fabs(p_entity.vx)), r128_from_real_um(ahx), dk);
	R128 gey = ghost_bound(r128_from_real_um(std::fabs(p_entity.vy)), r128_from_real_um(ahy), dk);
	R128 gez = ghost_bound(r128_from_real_um(std::fabs(p_entity.vz)), r128_from_real_um(ahz), dk);
	R128 cx = r128_from_real_um(p_entity.cx);
	R128 cy = r128_from_real_um(p_entity.cy);
	R128 cz = r128_from_real_um(p_entity.cz);
	Aabb ghost;
	ghost.min_x = r128_to_coord(r128_sub(cx, gex));
	ghost.max_x = r128_to_coord(r128_add(cx, gex));
	ghost.min_y = r128_to_coord(r128_sub(cy, gey));
	ghost.max_y = r128_to_coord(r128_add(cy, gey));
	ghost.min_z = r128_to_coord(r128_sub(cz, gez));
	ghost.max_z = r128_to_coord(r128_add(cz, gez));
	Aabb scene = scene_aabb();
	GhostSnap snap;
	snap.cx = p_entity.cx;
	snap.cy = p_entity.cy;
	snap.cz = p_entity.cz;
	snap.vx = std::fabs(p_entity.vx);
	snap.vy = std::fabs(p_entity.vy);
	snap.vz = std::fabs(p_entity.vz);
	snap.max_ahx = ahx;
	snap.max_ahy = ahy;
	snap.max_ahz = ahz;
	snap.per_delta = d;
	snap.ticks_since_snap = 0;
	snap.ghost_ey = r128_to_real_m(gey);
	snap.ghost_hilbert = hilbert_of_aabb(&ghost, &scene);
	return snap;
}

void update_snap(GhostSnap &r_snap, const FabricEntity &p_entity) {
	uint32_t t = r_snap.ticks_since_snap + 1;
	real_t ahx = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.ax));
	real_t ahy = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.ay));
	real_t ahz = std::max(ACCEL_FLOOR_M, std::fabs(p_entity.az));
	real_t nx = std::max(r_snap.max_ahx, ahx);
	real_t ny = std::max(r_snap.max_ahy, ahy);
	real_t nz = std::max(r_snap.max_ahz, ahz);
	real_t old_max = std::max(std::max(r_snap.max_ahx, r_snap.max_ahy), r_snap.max_ahz);
	real_t new_max = std::max(std::max(nx, ny), nz);
	uint32_t per_delta = r_snap.per_delta;
	if (new_max > old_max) {
		per_delta = snap_delta(std::max(std::max(r_snap.vx, r_snap.vy), r_snap.vz), new_max);
	}
	if (t >= per_delta) {
		r_snap = make_ghost_snap(p_entity);
		r_snap.max_ahx = std::max(r_snap.max_ahx, nx);
		r_snap.max_ahy = std::max(r_snap.max_ahy, ny);
		r_snap.max_ahz = std::max(r_snap.max_ahz, nz);
	} else {
		r_snap.max_ahx = nx;
		r_snap.max_ahy = ny;
		r_snap.max_ahz = nz;
		r_snap.per_delta = per_delta;
		r_snap.ticks_since_snap = t;
	}
}

Aabb ghost_aabb_from_snap(const GhostSnap &p_snap) {
	R128 t = r128_from_u32(p_snap.ticks_since_snap);
	R128 ex = ghost_bound(r128_from_real_um(p_snap.vx), r128_from_real_um(p_snap.max_ahx), t);
	R128 ey = ghost_bound(r128_from_real_um(p_snap.vy), r128_from_real_um(p_snap.max_ahy), t);
	R128 ez = ghost_bound(r128_from_real_um(p_snap.vz), r128_from_real_um(p_snap.max_ahz), t);
	R128 cx = r128_from_real_um(p_snap.cx);
	R128 cy = r128_from_real_um(p_snap.cy);
	R128 cz = r128_from_real_um(p_snap.cz);
	Aabb a;
	a.min_x = r128_to_coord(r128_sub(cx, ex));
	a.max_x = r128_to_coord(r128_add(cx, ex));
	a.min_y = r128_to_coord(r128_sub(cy, ey));
	a.max_y = r128_to_coord(r128_add(cy, ey));
	a.min_z = r128_to_coord(r128_sub(cz, ez));
	a.max_z = r128_to_coord(r128_add(cz, ez));
	return a;
}

void resolve_staging_timeouts(EntitySlot *p_slots, int p_capacity, int p_zone_id, const uint32_t p_srtt[2],
		const uint32_t p_rttvar[2], const bool p_rtt_measured[2], uint32_t p_hz, uint32_t p_tick) {
	for (int i = 0; i < p_capacity; i++) {
		if (p_slots[i].active && p_slots[i].is_staging) {
			int n = (p_slots[i].migration_target_zone == p_zone_id - 1) ? 0 : 1;
			uint32_t timeout = staging_timeout(p_srtt[n], p_rttvar[n], p_rtt_measured[n], p_hz);
			if (p_tick - p_slots[i].staging_send_tick >= timeout) {
				p_slots[i].is_staging = false;
				p_slots[i].migration_target_zone = -1;
				p_slots[i].hysteresis = 0;
			}
		}
	}
}

int accept_incoming_intents(EntitySlot *p_slots, int p_capacity, int &r_entity_count, int &r_free_hint,
		int p_zone_id, int p_from_zone, std::vector<Bytes> &r_inbox, uint64_t &r_xing_received) {
	int accepted = 0;
	for (const Bytes &data : r_inbox) {
		int offset = 0;
		while (offset + INTENT_SIZE <= int(data.size())) {
			int eid;
			int to_zone;
			uint32_t arrival;
			FabricEntity ent;
			if (unpack_intent(data.data() + offset, INTENT_SIZE, eid, to_zone, arrival, ent) &&
					to_zone == p_zone_id) {
				int free_idx = -1;
				for (int fi = 0; fi < p_capacity; fi++) {
					int idx = (r_free_hint + fi) % p_capacity;
					if (!p_slots[idx].active) {
						free_idx = idx;
						break;
					}
				}
				if (free_idx >= 0) {
					r_xing_received++;
					EntitySlot &s = p_slots[free_idx];
					s = EntitySlot();
					s.entity = ent;
					s.snap = make_ghost_snap(ent);
					s.active = true;
					s.is_incoming = true;
					s.incoming_from_zone = p_from_zone;
					r_entity_count++;
					r_free_hint = (free_idx + 1) % p_capacity;
					accepted++;
				}
			}
			offset += INTENT_SIZE;
		}
	}
	r_inbox.clear();
	return accepted;
}

int collect_migration_intents(EntitySlot *p_slots, int p_capacity, int p_zone_id, const NodeView &p_view,
		const uint32_t p_srtt[2], uint32_t p_tick, uint32_t p_hz, int p_budget, uint64_t &r_xing_started,
		uint64_t &r_migrations, std::vector<Bytes> &r_outbox, std::vector<int> &r_targets) {
	int sent = 0;
	uint32_t hysteresis = pbvh_hysteresis_threshold(p_hz);
	for (int i = 0; i < p_capacity && p_budget > 0; i++) {
		EntitySlot &s = p_slots[i];
		if (!s.active || s.is_staging || s.is_incoming || s.is_player_slot) {
			continue;
		}
		int target = RelZone::zone_for_hilbert(p_view, entity_hilbert(s.entity));
		if (target != p_zone_id) {
			s.hysteresis += 1;
			if (s.hysteresis >= hysteresis) {
				r_xing_started++;
				s.is_staging = true;
				s.staging_send_tick = p_tick;
				s.migration_target_zone = target;
				r_migrations += 1;
				int n = (target == p_zone_id - 1) ? 0 : 1;
				r_outbox.push_back(pack_intent(s.entity.global_id, target, p_tick + p_srtt[n], s.entity));
				r_targets.push_back(target);
				p_budget--;
				sent++;
			}
		} else {
			s.hysteresis = 0;
		}
	}
	return sent;
}

namespace {
int ghost_pair_noop(pbvh_eclass_id_t, pbvh_eclass_id_t, void *) {
	return 0;
}
} // namespace

int count_ghost_overlapping_pairs(const EntitySlot *p_slots, int p_capacity) {
	if (p_capacity <= 0) {
		return 0;
	}
	std::vector<pbvh_node_t> storage(p_capacity);
	std::vector<pbvh_node_id_t> sorted(p_capacity);
	std::vector<pbvh_internal_t> internals(2 * p_capacity);
	pbvh_tree_t tree = {};
	tree.nodes = storage.data();
	tree.capacity = uint32_t(storage.size());
	tree.root = PBVH_NULL_NODE;
	tree.free_head = PBVH_NULL_NODE;
	tree.sorted = sorted.data();
	tree.internals = internals.data();
	tree.internal_capacity = uint32_t(internals.size());
	tree.internal_root = PBVH_NULL_NODE;
	Aabb scene = scene_aabb();
	for (int i = 0; i < p_capacity; i++) {
		if (!p_slots[i].active) {
			continue;
		}
		Aabb g = ghost_aabb_from_snap(p_slots[i].snap);
		pbvh_tree_insert_h(&tree, pbvh_eclass_id_t(i), g, hilbert_of_aabb(&g, &scene));
	}
	pbvh_tree_build(&tree);
	return pbvh_tree_enumerate_pairs(&tree, ghost_pair_noop, nullptr);
}

void finalize_incoming(EntitySlot *p_slots, int p_capacity, std::vector<uint32_t> &r_acked_eids,
		std::vector<int> &r_acked_from) {
	for (int i = 0; i < p_capacity; i++) {
		if (p_slots[i].active && p_slots[i].is_incoming) {
			p_slots[i].is_incoming = false;
			r_acked_eids.push_back(uint32_t(p_slots[i].entity.global_id));
			r_acked_from.push_back(p_slots[i].incoming_from_zone);
		}
	}
}

bool apply_ack(EntitySlot *p_slots, int p_capacity, uint32_t p_eid, int &r_entity_count, int &r_free_hint) {
	for (int i = 0; i < p_capacity; i++) {
		if (p_slots[i].active && p_slots[i].is_staging && uint32_t(p_slots[i].entity.global_id) == p_eid) {
			p_slots[i].active = false;
			p_slots[i].is_staging = false;
			p_slots[i].migration_target_zone = -1;
			r_entity_count--;
			r_free_hint = i;
			return true;
		}
	}
	return false;
}

} // namespace fabric::zone
