// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// casync content-addressed storage, ported from entities-godot's multiplayer_fabric_asset.
#pragma once

#include "../transport/transport.h"

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fabric::casync {

constexpr int CHUNK_ID_BYTES = 32;
constexpr int CHUNK_MIN_BYTES = 16 * 1024;
constexpr int CHUNK_AVG_BYTES = 64 * 1024;
constexpr int CHUNK_MAX_BYTES = 256 * 1024;

using ChunkId = std::array<uint8_t, CHUNK_ID_BYTES>;
using Bytes = std::vector<uint8_t>;

struct CaibxChunk {
	ChunkId id;
	uint64_t start = 0;
	uint64_t size = 0;
};

struct Span {
	uint64_t start = 0;
	uint64_t size = 0;
};

ChunkId sha512_256(const uint8_t *p_data, uint64_t p_len);
std::string hex_from_id(const ChunkId &p_id);

// Cut points by desync's buzhash over a 48-byte window.
std::vector<Span> chunk_spans(const Bytes &p_data, int p_min = CHUNK_MIN_BYTES, int p_avg = CHUNK_AVG_BYTES,
		int p_max = CHUNK_MAX_BYTES);

// A .caibx index for the given chunks. Each table item holds the chunk's end offset.
Bytes write_caibx(const std::vector<CaibxChunk> &p_chunks, int p_min = CHUNK_MIN_BYTES,
		int p_avg = CHUNK_AVG_BYTES, int p_max = CHUNK_MAX_BYTES);
bool parse_caibx(const Bytes &p_bytes, std::vector<CaibxChunk> &r_chunks, std::string &r_error);

Bytes compress_chunk(const uint8_t *p_data, uint64_t p_len);
bool decompress_and_verify(const Bytes &p_compressed, const ChunkId &p_expected, Bytes &r_out, std::string &r_error);

// Compressed chunks by id: the desync store's content, held in memory.
class ChunkStore {
public:
	// Chunks the data, stores every chunk compressed, and returns the .caibx index.
	Bytes put(const Bytes &p_data);
	bool has(const ChunkId &p_id) const { return chunks.count(p_id) > 0; }
	const Bytes *get(const ChunkId &p_id) const;
	void put_compressed(const ChunkId &p_id, const Bytes &p_compressed) { chunks[p_id] = p_compressed; }
	size_t size() const { return chunks.size(); }

private:
	std::map<ChunkId, Bytes> chunks;
};

bool assemble(const Bytes &p_caibx, const ChunkStore &p_store, Bytes &r_out, std::string &r_error);

// Chunk requests and replies on CH_ASSET. A request is [CREQ][id]; a reply is
// [CRES][id][compressed bytes], or [CMIS][id] when the store lacks the chunk.
constexpr uint32_t CHUNK_REQUEST = 0x51455243u;
constexpr uint32_t CHUNK_REPLY = 0x53455243u;
constexpr uint32_t CHUNK_MISSING = 0x53494d43u;

// Answers every pending chunk request on the transport from the store.
int serve(Transport &p_transport, const ChunkStore &p_store);

// Fetches the chunks an index names from one peer into a local store, verifying each.
class Fetch {
public:
	bool begin(const Bytes &p_caibx, int p_peer, std::string &r_error);
	// Sends requests for chunks not yet asked for, and takes in replies. Returns true when done.
	bool poll(Transport &p_transport);
	bool failed() const { return !error.empty(); }
	const std::string &get_error() const { return error; }
	bool result(Bytes &r_out);
	const ChunkStore &local() const { return store; }

private:
	Bytes index;
	int peer = 0;
	std::vector<CaibxChunk> chunks;
	std::set<ChunkId> asked;
	ChunkStore store;
	std::string error;
};

} // namespace fabric::casync
