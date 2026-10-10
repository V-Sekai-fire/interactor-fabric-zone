// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// zone.elf: one fabric zone as a godot-sandbox guest. The host carries packets both ways and
// calls zone_tick once per physics tick.
#include <api.hpp>

#include "transport/frame_transport.h"
#include "zone/zone.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>

namespace {

fabric::FrameTransport g_transport;
std::unique_ptr<fabric::Zone> g_zone;
// The newest journal image, until the host takes it.
std::vector<uint8_t> g_journal_image;
bool g_journal_dirty = false;

void journal_flush(const uint8_t *p_data, uint64_t p_size, void *) {
	g_journal_image.assign(p_data, p_data + p_size);
	g_journal_dirty = true;
}

Variant text(const std::string &p_s) {
	return Variant(String(p_s));
}

} // namespace

static Variant zone_open(int zone_id, int zone_count, int capacity, int hz) {
	fabric::ZoneConfig c;
	c.zone_id = zone_id;
	c.zone_count = zone_count;
	c.capacity = capacity > 0 ? capacity : 1800;
	c.hz = hz > 0 ? uint32_t(hz) : 60;
	g_zone.reset(new fabric::Zone(c, &g_transport));
	return text("OK zone " + std::to_string(zone_id) + " of " + std::to_string(zone_count));
}

static Variant zone_journal_open(PackedArray<uint8_t> image) {
	if (!g_zone) {
		return text("FAIL: zone_open first");
	}
	g_zone->journal().set_flush(&journal_flush, nullptr);
	std::vector<uint8_t> bytes = image.fetch();
	if (!g_zone->open_journal(bytes)) {
		return text("FAIL: journal did not open");
	}
	return text("OK journal, " + std::to_string(bytes.size()) + " bytes replayed from the host, " +
			std::to_string(g_zone->get_entity_count()) + " entities restored");
}

// The journal image written since the last take, or an empty array when nothing changed.
static Variant zone_journal_take() {
	if (!g_journal_dirty) {
		return Variant(PackedArray<uint8_t>(std::vector<uint8_t>()));
	}
	g_journal_dirty = false;
	return Variant(PackedArray<uint8_t>(g_journal_image));
}

static Variant zone_connect(int peer, bool connected) {
	g_transport.set_connected(peer, connected);
	return Variant(true);
}

static Variant zone_packet_in(int peer, int channel, PackedArray<uint8_t> bytes) {
	std::vector<uint8_t> b = bytes.fetch();
	g_transport.receive(peer, channel, b.data(), int(b.size()));
	return Variant(true);
}

static Variant zone_tick() {
	if (!g_zone) {
		return Variant(PackedArray<uint8_t>(std::vector<uint8_t>()));
	}
	g_zone->tick();
	return Variant(PackedArray<uint8_t>(g_transport.take_frames()));
}

static Variant zone_spawn(int global_id, double x, double y, double z, PackedArray<uint8_t> payload) {
	if (!g_zone) {
		return Variant(int64_t(-1));
	}
	fabric::FabricEntity e;
	e.global_id = global_id;
	e.cx = x;
	e.cy = y;
	e.cz = z;
	std::vector<uint8_t> p = payload.fetch();
	std::memcpy(e.payload, p.data(), std::min(p.size(), sizeof(e.payload)));
	return Variant(int64_t(g_zone->spawn(e)));
}

static Variant zone_set_payload(int global_id, PackedArray<uint8_t> payload) {
	if (!g_zone) {
		return Variant(false);
	}
	uint32_t p[14] = {};
	std::vector<uint8_t> b = payload.fetch();
	std::memcpy(p, b.data(), std::min(b.size(), sizeof(p)));
	return Variant(g_zone->set_payload(global_id, p));
}

static Variant zone_despawn(int global_id) {
	if (!g_zone) {
		return Variant(false);
	}
	return Variant(g_zone->despawn(global_id));
}

static Variant zone_handover(int global_id, int target_zone) {
	return Variant(g_zone && g_zone->handover(global_id, target_zone));
}

static Variant zone_state(int global_id) {
	return Variant(int64_t(g_zone ? g_zone->state_of(global_id) : fabric::Zone::ABSENT));
}

// The ghosts this zone sees: rows of [gid u32][from zone i32][cx cy cz f64][payload 14 x u32].
static Variant zone_ghosts() {
	std::vector<uint8_t> out;
	if (g_zone) {
		for (const std::pair<const int, fabric::Ghost> &g : g_zone->ghosts()) {
			uint32_t gid = uint32_t(g.first);
			int32_t from = g.second.from_zone;
			double c[3] = { g.second.entity.cx, g.second.entity.cy, g.second.entity.cz };
			const uint8_t *parts[4] = { reinterpret_cast<const uint8_t *>(&gid),
				reinterpret_cast<const uint8_t *>(&from), reinterpret_cast<const uint8_t *>(c),
				reinterpret_cast<const uint8_t *>(g.second.entity.payload) };
			const size_t sizes[4] = { 4, 4, 24, 56 };
			for (int k = 0; k < 4; k++) {
				out.insert(out.end(), parts[k], parts[k] + sizes[k]);
			}
		}
	}
	return Variant(PackedArray<uint8_t>(out));
}

static Variant zone_status() {
	if (!g_zone) {
		return text("IDLE");
	}
	return text("tick " + std::to_string(g_zone->get_tick()) + " entities " + std::to_string(g_zone->get_entity_count()) +
			" ghosts " + std::to_string(g_zone->ghosts().size()) + " xing_started " +
			std::to_string(g_zone->xing_started) + " xing_done " + std::to_string(g_zone->xing_done) +
			" xing_received " + std::to_string(g_zone->xing_received) + " journal_flushes " +
			std::to_string(g_zone->journal().flushes()));
}

int main() {
	ADD_API_FUNCTION(zone_open, "String", "int zone_id, int zone_count, int capacity, int hz", "Make this guest one fabric zone");
	ADD_API_FUNCTION(zone_journal_open, "String", "PackedByteArray image", "Open the crash journal from a previous flush (empty: a new journal)");
	ADD_API_FUNCTION(zone_journal_take, "PackedByteArray", "", "The journal image flushed since the last take; the host writes it where it keeps journals");
	ADD_API_FUNCTION(zone_connect, "bool", "int peer, bool connected", "Tell the zone a peer is reachable");
	ADD_API_FUNCTION(zone_packet_in, "bool", "int peer, int channel, PackedByteArray bytes", "A packet the host received for this zone");
	ADD_API_FUNCTION(zone_tick, "PackedByteArray", "", "One tick; returns frames [peer i32][channel u32][len u32][bytes], peer -1 = broadcast");
	ADD_API_FUNCTION(zone_spawn, "int", "int global_id, float x, float y, float z, PackedByteArray payload", "A new entity this zone owns; returns its slot");
	ADD_API_FUNCTION(zone_set_payload, "bool", "int global_id, PackedByteArray payload", "Replace an owned entity's 56-byte payload (a wardrobe entry: its .caibx index id)");
	ADD_API_FUNCTION(zone_despawn, "bool", "int global_id", "Remove an owned entity");
	ADD_API_FUNCTION(zone_handover, "bool", "int global_id, int target_zone", "Hand an owned entity to another zone (OWNED -> STAGING)");
	ADD_API_FUNCTION(zone_state, "int", "int global_id", "0 absent, 1 owned, 2 staging, 3 incoming");
	ADD_API_FUNCTION(zone_ghosts, "PackedByteArray", "", "Rows other zones published that this zone sees");
	ADD_API_FUNCTION(zone_status, "String", "", "Counters");
	halt();
}
