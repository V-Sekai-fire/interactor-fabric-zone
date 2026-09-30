// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// asset.elf: casync content-addressed storage as a godot-sandbox guest. A garment is stored as
// compressed chunks under a .caibx index; another peer fetches it chunk by chunk on CH_ASSET.
#include <api.hpp>

#include "casync/casync.h"
#include "transport/frame_transport.h"

#include <string>

namespace {

fabric::FrameTransport g_transport;
fabric::casync::ChunkStore g_store;
fabric::casync::Fetch g_fetch;

Variant text(const std::string &p_s) {
	return Variant(String(p_s));
}

} // namespace

static Variant asset_put(PackedArray<uint8_t> data) {
	return Variant(PackedArray<uint8_t>(g_store.put(data.fetch())));
}

// The id a ghost carries: SHA-512/256 of the index.
static Variant asset_index_id(PackedArray<uint8_t> index) {
	std::vector<uint8_t> b = index.fetch();
	fabric::casync::ChunkId id = fabric::casync::sha512_256(b.data(), b.size());
	return Variant(PackedArray<uint8_t>(id.data(), id.size()));
}

static Variant asset_packet_in(int peer, int channel, PackedArray<uint8_t> bytes) {
	std::vector<uint8_t> b = bytes.fetch();
	g_transport.receive(peer, channel, b.data(), int(b.size()));
	return Variant(true);
}

static Variant asset_serve() {
	fabric::casync::serve(g_transport, g_store);
	return Variant(PackedArray<uint8_t>(g_transport.take_frames()));
}

static Variant asset_fetch_begin(PackedArray<uint8_t> index, int peer) {
	std::string err;
	if (!g_fetch.begin(index.fetch(), peer, err)) {
		return text("FAIL: " + err);
	}
	return text("OK");
}

// 0 fetching, 1 done, -1 failed; the frames to send go out through asset_frames.
static Variant asset_fetch_poll() {
	bool done = g_fetch.poll(g_transport);
	return Variant(int64_t(g_fetch.failed() ? -1 : (done ? 1 : 0)));
}

static Variant asset_frames() {
	return Variant(PackedArray<uint8_t>(g_transport.take_frames()));
}

static Variant asset_fetch_result() {
	std::vector<uint8_t> out;
	if (!g_fetch.result(out)) {
		return Variant(PackedArray<uint8_t>(std::vector<uint8_t>()));
	}
	return Variant(PackedArray<uint8_t>(out));
}

static Variant asset_status() {
	return text("chunks " + std::to_string(g_store.size()) + (g_fetch.failed() ? " fetch error: " + g_fetch.get_error() : ""));
}

int main() {
	ADD_API_FUNCTION(asset_put, "PackedByteArray", "PackedByteArray data", "Chunk and store data; returns its .caibx index");
	ADD_API_FUNCTION(asset_index_id, "PackedByteArray", "PackedByteArray index", "SHA-512/256 of an index: the id a ghost carries");
	ADD_API_FUNCTION(asset_packet_in, "bool", "int peer, int channel, PackedByteArray bytes", "A packet the host received for this guest");
	ADD_API_FUNCTION(asset_serve, "PackedByteArray", "", "Answer pending chunk requests; returns frames to send");
	ADD_API_FUNCTION(asset_fetch_begin, "String", "PackedByteArray index, int peer", "Start fetching an asset from a peer");
	ADD_API_FUNCTION(asset_fetch_poll, "int", "", "0 fetching, 1 done, -1 failed");
	ADD_API_FUNCTION(asset_frames, "PackedByteArray", "", "Frames to send: [peer i32][channel u32][len u32][bytes]");
	ADD_API_FUNCTION(asset_fetch_result, "PackedByteArray", "", "The fetched asset, reassembled and verified");
	ADD_API_FUNCTION(asset_status, "String", "", "Counters");
	halt();
}
