// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// One fabric zone: FabricZone's server tick from entities-godot's multiplayer_fabric, driven by
// the guest's tick over a Transport instead of the engine's SceneTree and MultiplayerPeer.
#pragma once

#include "../transport/transport.h"
#include "journal.h"
#include "pose.h"
#include "zone_core.h"

#include <map>
#include <vector>

namespace fabric {

struct ZoneConfig {
	int zone_id = 0;
	int zone_count = 1;
	int capacity = 1800;
	uint32_t hz = 60;
	// Transport peer ids: zone z is peer z; player p is peer PLAYER_PEER_BASE + p.
	int player_peer_base = 1000;
	// The control for the single-owner test: hand over without entering STAGING.
	bool plant_double_handover = false;
};

// A row another zone published: seen here, owned there.
struct Ghost {
	FabricEntity entity;
	int from_zone = -1;
	uint32_t seen_tick = 0;
	uint32_t hlc = 0;
};

class Zone {
public:
	enum State {
		ABSENT,
		OWNED,
		STAGING,
		INCOMING,
	};

	static constexpr int PLAYER_ENTITY_BASE = 2000000;
	static constexpr uint32_t PLAYER_SLOT_TIMEOUT_SECONDS = 3;
	static constexpr uint32_t PING_INTERVAL_SECONDS = 8;
	static constexpr int MAX_MIGRATIONS_PER_TICK = 50;
	static constexpr uint32_t GHOST_TIMEOUT_TICKS = 30;

	Zone(const ZoneConfig &p_config, Transport *p_transport);

	void tick();

	// A new entity this zone owns (the worker's garment, a stroke knot). Returns its slot or -1.
	int spawn(const FabricEntity &p_entity);
	// OWNED -> STAGING and an intent to the target zone: the hand-over the fabric makes on a
	// boundary crossing, made on request.
	bool handover(int p_global_id, int p_target_zone);
	bool set_payload(int p_global_id, const uint32_t p_payload[14]);

	State state_of(int p_global_id) const;
	const FabricEntity *entity(int p_global_id) const;
	const std::map<int, Ghost> &ghosts() const { return ghost_rows; }
	const std::map<uint32_t, pose::Pose> &poses() const { return player_poses; }
	uint32_t get_tick() const { return tick_count; }
	int get_entity_count() const { return entity_count; }
	int ghost_pairs() const { return zone::count_ghost_overlapping_pairs(slots.data(), config.capacity); }
	Journal &journal() { return zone_journal; }

	uint64_t xing_started = 0;
	uint64_t xing_done = 0;
	uint64_t xing_received = 0;
	uint64_t migrations = 0;

private:
	ZoneConfig config;
	Transport *transport;
	std::vector<EntitySlot> slots;
	int entity_count = 0;
	int free_hint = 0;
	uint32_t tick_count = 0;
	zone::NodeView node_view;
	RelZone::HLC hlc;
	uint32_t srtt[2];
	uint32_t rttvar[2];
	bool rtt_measured[2] = { false, false };
	uint32_t ping_next[2] = { 0, 0 };
	uint32_t ping_send_tick[2] = { 0, 0 };
	std::map<int, std::vector<zone::Bytes>> inbox_by_zone;
	std::map<uint32_t, int> player_slot;
	std::map<uint32_t, pose::Pose> player_poses;
	std::map<int, Ghost> ghost_rows;
	Journal zone_journal;

	int alloc_slot();
	int neighbor_index(int p_zone) const { return p_zone == config.zone_id - 1 ? 0 : 1; }
	bool is_player_peer(int p_peer) const { return p_peer >= config.player_peer_base; }
	void handle_migration();
	void handle_players();
	void handle_interest();
	void publish_interest();
	void send_control(int p_peer, uint32_t p_field, uint32_t p_magic);
};

} // namespace fabric
