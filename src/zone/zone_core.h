// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// FabricZone's static migration and ghost functions, ported from entities-godot's
// multiplayer_fabric/fabric_zone.cpp with the engine containers replaced by std ones.
#pragma once

#include "relativistic_zone.h"
#include "zone_types.h"

#include "pbvh_adapter.h"

#include <cstdint>
#include <vector>

namespace fabric::zone {

constexpr int MAX_ZONES = 32;
constexpr int INTENT_SIZE = 144; // eid u64, to u32, arrival u32, 9 x f64, payload 14 x u32
constexpr int ROW_SIZE = 100; // one CH_INTEREST row
constexpr real_t SIM_BOUND = 15.0;
constexpr real_t V_MAX = PBVH_V_MAX_PHYSICAL_DEFAULT * 0.000001;
constexpr real_t ACCEL_FLOOR_M = PBVH_ACCEL_FLOOR_DEFAULT * 0.000001;
constexpr float V_SCALE = 32767.0f / (PBVH_V_MAX_PHYSICAL_DEFAULT * 1.0e-6f);
constexpr float A_SCALE = 32767.0f / (2.0f * PBVH_V_MAX_PHYSICAL_DEFAULT * 1.0e-6f);

constexpr uint32_t PING_MAGIC = 0x50494E47u;
constexpr uint32_t PONG_MAGIC = 0x504F4E47u;
constexpr uint32_t ACK_MAGIC = 0x41434B4Bu;

using Bytes = std::vector<uint8_t>;
using NodeView = RelZone::NodeView<MAX_ZONES>;

Bytes pack_intent(int p_eid, int p_to, uint32_t p_arrival, const FabricEntity &p_entity);
bool unpack_intent(const uint8_t *p_data, int p_size, int &r_eid, int &r_to, uint32_t &r_arrival,
		FabricEntity &r_entity);

uint32_t staging_timeout(uint32_t p_srtt, uint32_t p_rttvar, bool p_rtt_measured, uint32_t p_hz);

Aabb scene_aabb();
uint32_t entity_hilbert(const FabricEntity &p_entity);
GhostSnap make_ghost_snap(const FabricEntity &p_entity);
void update_snap(GhostSnap &r_snap, const FabricEntity &p_entity);
Aabb ghost_aabb_from_snap(const GhostSnap &p_snap);

// The four migration sub-routines, as in FabricZone (public static for testability there too).
void resolve_staging_timeouts(EntitySlot *p_slots, int p_capacity, int p_zone_id, const uint32_t p_srtt[2],
		const uint32_t p_rttvar[2], const bool p_rtt_measured[2], uint32_t p_hz, uint32_t p_tick);
int accept_incoming_intents(EntitySlot *p_slots, int p_capacity, int &r_entity_count, int &r_free_hint,
		int p_zone_id, int p_from_zone, std::vector<Bytes> &r_inbox, uint64_t &r_xing_received);
int collect_migration_intents(EntitySlot *p_slots, int p_capacity, int p_zone_id, const NodeView &p_view,
		const uint32_t p_srtt[2], uint32_t p_tick, uint32_t p_hz, int p_budget, uint64_t &r_xing_started,
		uint64_t &r_migrations, std::vector<Bytes> &r_outbox, std::vector<int> &r_targets);
int count_ghost_overlapping_pairs(const EntitySlot *p_slots, int p_capacity);

// INCOMING -> OWNED; returns the ids to ACK and the zones they came from.
void finalize_incoming(EntitySlot *p_slots, int p_capacity, std::vector<uint32_t> &r_acked_eids,
		std::vector<int> &r_acked_from);
// An ACK resolves the matching STAGING slot: the entity leaves this zone.
bool apply_ack(EntitySlot *p_slots, int p_capacity, uint32_t p_eid, int &r_entity_count, int &r_free_hint);

} // namespace fabric::zone
