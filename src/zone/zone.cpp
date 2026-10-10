// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "zone.h"

#include <algorithm>
#include <cstring>

namespace fabric {

Zone::Zone(const ZoneConfig &p_config, Transport *p_transport) :
		config(p_config), transport(p_transport), slots(size_t(p_config.capacity)) {
	node_view = RelZone::node_view_from_zone_count<zone::MAX_ZONES>(size_t(config.zone_id), config.zone_count);
	for (int n = 0; n < 2; n++) {
		srtt[n] = PBVH_LATENCY_TICKS_DEFAULT;
		rttvar[n] = PBVH_LATENCY_TICKS_DEFAULT / 2;
	}
}

int Zone::alloc_slot() {
	for (int fi = 0; fi < config.capacity; fi++) {
		int idx = (free_hint + fi) % config.capacity;
		if (!slots[idx].active) {
			free_hint = (idx + 1) % config.capacity;
			return idx;
		}
	}
	return -1;
}

int Zone::spawn(const FabricEntity &p_entity) {
	int idx = alloc_slot();
	if (idx < 0) {
		return -1;
	}
	slots[idx] = EntitySlot();
	slots[idx].entity = p_entity;
	slots[idx].snap = zone::make_ghost_snap(p_entity);
	slots[idx].active = true;
	entity_count++;
	zone_journal.spawn(idx, p_entity);
	return idx;
}

bool Zone::despawn(int p_global_id) {
	for (int i = 0; i < config.capacity; i++) {
		if (slot_owned(slots[i]) && slots[i].entity.global_id == p_global_id) {
			slots[i].active = false;
			entity_count--;
			free_hint = i;
			zone_journal.despawn(i, p_global_id);
			return true;
		}
	}
	return false;
}

bool Zone::open_journal(const std::vector<uint8_t> &p_image) {
	if (!zone_journal.open(p_image)) {
		return false;
	}
	if (p_image.empty()) {
		return true;
	}
	zone_journal.replay(config.capacity, slots.data(), entity_count);
	for (int i = 0; i < config.capacity; i++) {
		if (slots[i].active) {
			slots[i].snap = zone::make_ghost_snap(slots[i].entity);
		}
	}
	return true;
}

bool Zone::handover(int p_global_id, int p_target_zone) {
	for (int i = 0; i < config.capacity; i++) {
		EntitySlot &s = slots[i];
		if (!slot_owned(s) || s.entity.global_id != p_global_id) {
			continue;
		}
		if (!config.plant_double_handover) {
			s.is_staging = true;
			s.staging_send_tick = tick_count;
			s.migration_target_zone = p_target_zone;
		}
		xing_started++;
		migrations++;
		zone::Bytes pkt = zone::pack_intent(p_global_id, p_target_zone,
				tick_count + srtt[neighbor_index(p_target_zone)], s.entity);
		if (config.plant_intent_without_payload) {
			std::fill(pkt.begin() + 88, pkt.end(), uint8_t(0));
		}
		transport->send(p_target_zone, CH_MIGRATION, pkt.data(), int(pkt.size()));
		return true;
	}
	return false;
}

bool Zone::set_payload(int p_global_id, const uint32_t p_payload[14]) {
	for (int i = 0; i < config.capacity; i++) {
		if (slot_owned(slots[i]) && slots[i].entity.global_id == p_global_id) {
			std::memcpy(slots[i].entity.payload, p_payload, sizeof(slots[i].entity.payload));
			zone_journal.payload_update(i, slots[i].entity);
			return true;
		}
	}
	return false;
}

Zone::State Zone::state_of(int p_global_id) const {
	for (const EntitySlot &s : slots) {
		if (s.active && s.entity.global_id == p_global_id) {
			return s.is_staging ? STAGING : (s.is_incoming ? INCOMING : OWNED);
		}
	}
	return ABSENT;
}

const FabricEntity *Zone::entity(int p_global_id) const {
	for (const EntitySlot &s : slots) {
		if (s.active && s.entity.global_id == p_global_id) {
			return &s.entity;
		}
	}
	return nullptr;
}

void Zone::send_control(int p_peer, uint32_t p_field, uint32_t p_magic) {
	uint8_t buf[8];
	std::memcpy(buf + 0, &p_field, 4);
	std::memcpy(buf + 4, &p_magic, 4);
	transport->send(p_peer, CH_MIGRATION, buf, 8);
}

void Zone::handle_migration() {
	uint32_t floor_ticks = pbvh_latency_ticks(config.hz);
	for (Packet &p : transport->drain(CH_MIGRATION)) {
		if (p.bytes.size() == 8) {
			uint32_t field;
			uint32_t magic;
			std::memcpy(&field, p.bytes.data() + 0, 4);
			std::memcpy(&magic, p.bytes.data() + 4, 4);
			if (magic == zone::PING_MAGIC) {
				send_control(p.peer, field, zone::PONG_MAGIC);
			} else if (magic == zone::PONG_MAGIC) {
				// Jacobson/Karels (1988): RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - s|, SRTT = 7/8 SRTT + 1/8 s.
				uint32_t one_way = (tick_count - field + 1) / 2;
				uint32_t sample = std::max(one_way, floor_ticks);
				int n = neighbor_index(p.peer);
				if (ping_send_tick[n] == field) {
					if (!rtt_measured[n]) {
						srtt[n] = sample;
						rttvar[n] = sample / 2;
						rtt_measured[n] = true;
					} else {
						uint32_t delta = srtt[n] > sample ? srtt[n] - sample : sample - srtt[n];
						rttvar[n] = (3 * rttvar[n] + delta) / 4;
						srtt[n] = std::max((7 * srtt[n] + sample) / 8, floor_ticks);
					}
				}
			} else if (magic == zone::ACK_MAGIC) {
				int slot = -1;
				for (int i = 0; i < config.capacity; i++) {
					if (slots[i].active && slots[i].is_staging && uint32_t(slots[i].entity.global_id) == field) {
						slot = i;
						break;
					}
				}
				if (zone::apply_ack(slots.data(), config.capacity, field, entity_count, free_hint)) {
					xing_done++;
					zone_journal.despawn(slot, int(field));
				}
			}
		} else if (p.bytes.size() >= size_t(zone::INTENT_SIZE)) {
			inbox_by_zone[p.peer].push_back(std::move(p.bytes));
		}
	}
	for (std::pair<const int, std::vector<zone::Bytes>> &in : inbox_by_zone) {
		zone::accept_incoming_intents(slots.data(), config.capacity, entity_count, free_hint, config.zone_id, in.first,
				in.second, xing_received);
	}
	inbox_by_zone.clear();
}

void Zone::handle_players() {
	for (const Packet &p : transport->drain(CH_PLAYER)) {
		pose::Pose pose_in;
		if (!pose::decode(p.bytes.data(), int(p.bytes.size()), pose_in)) {
			continue;
		}
		// A player speaks only for itself: its id is its transport peer, never the packet's claim.
		if (!is_player_peer(p.peer) || pose_in.player_id != uint32_t(p.peer - config.player_peer_base)) {
			continue;
		}
		uint32_t pid = pose_in.player_id;
		player_poses[pid] = pose_in;
		int idx = -1;
		std::map<uint32_t, int>::iterator it = player_slot.find(pid);
		if (it != player_slot.end() && slots[it->second].active && slots[it->second].is_player_slot) {
			idx = it->second;
		} else {
			idx = alloc_slot();
			if (idx < 0) {
				continue;
			}
			slots[idx] = EntitySlot();
			slots[idx].active = true;
			slots[idx].is_player_slot = true;
			slots[idx].entity.global_id = int(uint32_t(PLAYER_ENTITY_BASE) + pid);
			slots[idx].entity.payload[0] = (1u << 24) | ((pid & 0xFFFFu) << 8);
			entity_count++;
			player_slot[pid] = idx;
		}
		FabricEntity &e = slots[idx].entity;
		e.cx = pose_in.root[0];
		e.cy = pose_in.root[1];
		e.cz = pose_in.root[2];
		slots[idx].last_update_tick = tick_count;
		slots[idx].snap = zone::make_ghost_snap(e);
	}
}

void Zone::handle_interest() {
	for (const Packet &p : transport->drain(CH_INTEREST)) {
		if (is_player_peer(p.peer)) {
			continue;
		}
		for (size_t off = 0; off + zone::ROW_SIZE <= p.bytes.size(); off += zone::ROW_SIZE) {
			const uint8_t *r = p.bytes.data() + off;
			Ghost g;
			uint32_t gid;
			std::memcpy(&gid, r + 0, 4);
			std::memcpy(&g.entity.cx, r + 4, 8);
			std::memcpy(&g.entity.cy, r + 12, 8);
			std::memcpy(&g.entity.cz, r + 20, 8);
			std::memcpy(&g.hlc, r + 40, 4);
			std::memcpy(g.entity.payload, r + 44, 56);
			g.entity.global_id = int(gid);
			g.from_zone = p.peer;
			g.seen_tick = tick_count;
			// A row for an entity this zone holds is its own echo, not a ghost.
			if (state_of(int(gid)) == ABSENT) {
				ghost_rows[int(gid)] = g;
			}
		}
		// Relay neighbour rows to this zone's players, as the fabric's AOI band relay does.
		for (const std::pair<const uint32_t, int> &pl : player_slot) {
			transport->send(config.player_peer_base + int(pl.first), CH_INTEREST, p.bytes.data(), int(p.bytes.size()));
		}
	}
	for (std::map<int, Ghost>::iterator it = ghost_rows.begin(); it != ghost_rows.end();) {
		if (tick_count - it->second.seen_tick > GHOST_TIMEOUT_TICKS || state_of(it->first) != ABSENT) {
			it = ghost_rows.erase(it);
		} else {
			++it;
		}
	}
}

void Zone::publish_interest() {
	std::vector<uint8_t> buf;
	hlc = RelZone::HLC::advance(hlc, uint64_t(tick_count));
	hlc.l = 0;
	for (int i = 0; i < config.capacity; i++) {
		EntitySlot &s = slots[i];
		if (!s.active || s.is_incoming) {
			continue;
		}
		zone::update_snap(s.snap, s.entity);
		const FabricEntity &e = s.entity;
		uint8_t row[zone::ROW_SIZE];
		uint32_t gid = uint32_t(e.global_id);
		double c[3] = { e.cx, e.cy, e.cz };
		int16_t q[6] = {
			int16_t(std::clamp(int(e.vx * zone::V_SCALE), -32767, 32767)),
			int16_t(std::clamp(int(e.vy * zone::V_SCALE), -32767, 32767)),
			int16_t(std::clamp(int(e.vz * zone::V_SCALE), -32767, 32767)),
			int16_t(std::clamp(int(e.ax * zone::A_SCALE), -32767, 32767)),
			int16_t(std::clamp(int(e.ay * zone::A_SCALE), -32767, 32767)),
			int16_t(std::clamp(int(e.az * zone::A_SCALE), -32767, 32767)),
		};
		uint32_t wire = hlc.to_wire();
		hlc.l++;
		std::memcpy(row + 0, &gid, 4);
		std::memcpy(row + 4, c, 24);
		std::memcpy(row + 28, q, 12);
		std::memcpy(row + 40, &wire, 4);
		std::memcpy(row + 44, e.payload, 56);
		buf.insert(buf.end(), row, row + zone::ROW_SIZE);
	}
	for (size_t off = 0; off < buf.size(); off += 1200) {
		size_t n = std::min(size_t(1200), buf.size() - off);
		transport->broadcast(CH_INTEREST, buf.data() + off, int(n));
	}
	for (const std::pair<const uint32_t, pose::Pose> &pp : player_poses) {
		std::vector<uint8_t> enc = pose::encode(pp.second);
		for (const std::pair<const uint32_t, int> &pl : player_slot) {
			if (pl.first != pp.first) {
				transport->send(config.player_peer_base + int(pl.first), CH_PLAYER, enc.data(), int(enc.size()));
			}
		}
	}
}

void Zone::tick() {
	uint32_t hz = config.hz;
	zone_journal.set_now(int64_t(tick_count));
	for (int n = 0; n < 2; n++) {
		int nb = n == 0 ? config.zone_id - 1 : config.zone_id + 1;
		if (nb < 0 || nb >= config.zone_count || !transport->is_connected(nb) || tick_count < ping_next[n]) {
			continue;
		}
		send_control(nb, tick_count, zone::PING_MAGIC);
		ping_send_tick[n] = tick_count;
		ping_next[n] = tick_count + PING_INTERVAL_SECONDS * hz;
	}
	handle_migration();
	handle_players();

	std::vector<zone::Bytes> outbox;
	std::vector<int> targets;
	zone::collect_migration_intents(slots.data(), config.capacity, config.zone_id, node_view, srtt, tick_count, hz,
			MAX_MIGRATIONS_PER_TICK, xing_started, migrations, outbox, targets);
	for (size_t i = 0; i < outbox.size(); i++) {
		transport->send(targets[i], CH_MIGRATION, outbox[i].data(), int(outbox[i].size()));
	}

	std::vector<uint32_t> acked;
	std::vector<int> acked_from;
	zone::finalize_incoming(slots.data(), config.capacity, acked, acked_from);
	for (size_t i = 0; i < acked.size(); i++) {
		send_control(acked_from[i], acked[i], zone::ACK_MAGIC);
		for (int s = 0; s < config.capacity; s++) {
			if (slots[s].active && uint32_t(slots[s].entity.global_id) == acked[i]) {
				zone_journal.spawn(s, slots[s].entity);
				break;
			}
		}
	}

	zone::resolve_staging_timeouts(slots.data(), config.capacity, config.zone_id, srtt, rttvar, rtt_measured, hz,
			tick_count);

	uint32_t player_timeout = PLAYER_SLOT_TIMEOUT_SECONDS * hz;
	for (int i = 0; i < config.capacity; i++) {
		if (slots[i].active && slots[i].is_player_slot && tick_count - slots[i].last_update_tick >= player_timeout) {
			uint32_t pid = uint32_t(slots[i].entity.global_id - PLAYER_ENTITY_BASE);
			player_slot.erase(pid);
			player_poses.erase(pid);
			slots[i].active = false;
			slots[i].is_player_slot = false;
			entity_count--;
			free_hint = i;
		}
	}

	handle_interest();
	publish_interest();
	tick_count++;
}

} // namespace fabric
