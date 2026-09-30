// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The fabric's plain data, from entities-godot's multiplayer_fabric (fabric_zone_types.h),
// in double precision to match the engine's precision=double build.
#pragma once

#include <cstdint>

namespace fabric {

using real_t = double;

// An entity, in metres. payload[0] = class(8b) | owner(16b) | flags(8b); the rest is per class
// (fabric_zone_types.h documents the concrete layouts).
struct FabricEntity {
	real_t cx = 0.0, cy = 0.0, cz = 0.0;
	real_t vx = 0.0, vy = 0.0, vz = 0.0;
	real_t ax = 0.0, ay = 0.0, az = 0.0;
	int global_id = 0;
	uint32_t payload[14] = {};
};

struct GhostSnap {
	real_t cx = 0.0, cy = 0.0, cz = 0.0;
	real_t vx = 0.0, vy = 0.0, vz = 0.0;
	real_t max_ahx = 0.0, max_ahy = 0.0, max_ahz = 0.0;
	uint32_t per_delta = 1;
	uint32_t ticks_since_snap = 0;
	real_t ghost_ey = 0.0;
	uint32_t ghost_hilbert = 0;
};

// Migration state (Lean: Fabric.lean MigrationState):
//   OWNED    active, !is_staging, !is_incoming
//   STAGING  active, is_staging              zone A sent the intent
//   INCOMING active, is_incoming             zone B received it
// OWNED -> STAGING -> gone on ACK (or back to OWNED on timeout); INCOMING -> OWNED one tick later.
struct EntitySlot {
	FabricEntity entity;
	GhostSnap snap;
	uint32_t hysteresis = 0;
	bool active = false;
	bool is_staging = false;
	uint32_t staging_send_tick = 0;
	int migration_target_zone = -1;
	bool is_incoming = false;
	int incoming_from_zone = -1;
	bool is_player_slot = false;
	uint32_t last_update_tick = 0;
};

inline bool slot_owned(const EntitySlot &p_slot) {
	return p_slot.active && !p_slot.is_staging && !p_slot.is_incoming;
}

} // namespace fabric
