// SPDX-FileCopyrightText: 2014-present Godot Engine contributors (see AUTHORS.md)
// SPDX-FileCopyrightText: 2007-2014 Juan Linietsky, Ariel Manzur
// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "casync.h"

#include <zstd.h>

#include <cstring>

#include "sha512_tables.inc"

namespace fabric::casync {

#include "buzhash_table.inc"

namespace {

constexpr uint64_t CA_FORMAT_INDEX = 0x96824d9c7b129ff9ULL;
constexpr uint64_t CA_FORMAT_TABLE = 0xe75b9e112f17417dULL;
constexpr uint64_t CA_FORMAT_TABLE_TAIL_MARKER = 0x4b4f050e5549ecd1ULL;
constexpr uint64_t CA_FORMAT_SHA512_256 = 0x2000000000000000ULL;
constexpr uint64_t CA_FORMAT_EXCLUDE_NODUMP = 0x8000000000000000ULL;
constexpr uint64_t CA_FORMAT_INDEX_SIZE = 48;
constexpr uint64_t CA_MAX_UINT64 = 0xFFFFFFFFFFFFFFFFULL;
constexpr int WINDOW = 48;

struct Cursor {
	const uint8_t *data;
	uint64_t size;
	uint64_t pos = 0;

	bool u64(uint64_t &r_value) {
		if (pos + 8 > size) {
			return false;
		}
		r_value = 0;
		for (int i = 0; i < 8; i++) {
			r_value |= uint64_t(data[pos + i]) << (i * 8);
		}
		pos += 8;
		return true;
	}

	bool bytes(uint8_t *r_dst, uint64_t p_n) {
		if (pos + p_n > size) {
			return false;
		}
		std::memcpy(r_dst, data + pos, p_n);
		pos += p_n;
		return true;
	}
};

void push_u64(Bytes &r_out, uint64_t p_v) {
	for (int b = 0; b < 8; b++) {
		r_out.push_back(uint8_t((p_v >> (b * 8)) & 0xFF));
	}
}

uint32_t rol32(uint32_t p_v, int p_s) {
	p_s &= 31;
	return p_s == 0 ? p_v : (p_v << p_s) | (p_v >> (32 - p_s));
}

void put_u32(Bytes &r_out, uint32_t p_v) {
	for (int b = 0; b < 4; b++) {
		r_out.push_back(uint8_t((p_v >> (b * 8)) & 0xFF));
	}
}

uint32_t get_u32(const uint8_t *p_data) {
	return uint32_t(p_data[0]) | (uint32_t(p_data[1]) << 8) | (uint32_t(p_data[2]) << 16) |
			(uint32_t(p_data[3]) << 24);
}

} // namespace

ChunkId sha512_256(const uint8_t *p_data, uint64_t p_len) {
	uint64_t s[8];
	std::memcpy(s, IV512_256, sizeof(IV512_256));
	uint64_t remaining = p_len;
	const uint8_t *cur = p_data;
	while (remaining >= 128) {
		sha512_compress(s, cur);
		cur += 128;
		remaining -= 128;
	}
	uint8_t tail[256];
	if (remaining > 0) {
		std::memcpy(tail, cur, remaining);
	}
	tail[remaining] = 0x80;
	uint64_t tail_len = remaining + 1;
	uint64_t blocks = tail_len > 112 ? 2 : 1;
	uint64_t pad_to = blocks * 128;
	std::memset(tail + tail_len, 0, pad_to - tail_len);
	uint64_t bit_len = p_len * 8ULL;
	for (int i = 0; i < 8; i++) {
		tail[pad_to - 1 - i] = uint8_t((bit_len >> (i * 8)) & 0xFF);
	}
	for (uint64_t i = 0; i < blocks; i++) {
		sha512_compress(s, tail + i * 128);
	}
	ChunkId out;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 8; j++) {
			out[i * 8 + j] = uint8_t((s[i] >> ((7 - j) * 8)) & 0xFF);
		}
	}
	return out;
}

std::string hex_from_id(const ChunkId &p_id) {
	static const char HEX[] = "0123456789abcdef";
	std::string out;
	for (uint8_t b : p_id) {
		out.push_back(HEX[(b >> 4) & 0x0F]);
		out.push_back(HEX[b & 0x0F]);
	}
	return out;
}

std::vector<Span> chunk_spans(const Bytes &p_data, int p_min, int p_avg, int p_max) {
	double denom = -1.42888852e-7 * double(p_avg) + 1.33237515;
	uint32_t discriminator = uint32_t(double(p_avg) / denom);
	std::vector<Span> spans;
	uint32_t h = 0;
	uint8_t window[WINDOW] = {};
	int widx = 0;
	uint64_t chunk_start = 0;
	uint64_t n = p_data.size();
	for (uint64_t i = 0; i < n; i++) {
		uint8_t out = window[widx];
		uint8_t in = p_data[i];
		window[widx] = in;
		widx = (widx + 1) % WINDOW;
		h = rol32(h, 1) ^ rol32(kBuzhashTable[out], WINDOW) ^ kBuzhashTable[in];
		uint64_t len = i - chunk_start + 1;
		if (len < uint64_t(p_min)) {
			continue;
		}
		if (len >= uint64_t(p_max) || (discriminator != 0 && h % discriminator == discriminator - 1)) {
			spans.push_back({ chunk_start, len });
			chunk_start = i + 1;
			h = 0;
			std::memset(window, 0, WINDOW);
			widx = 0;
		}
	}
	if (chunk_start < n) {
		spans.push_back({ chunk_start, n - chunk_start });
	}
	return spans;
}

Bytes write_caibx(const std::vector<CaibxChunk> &p_chunks, int p_min, int p_avg, int p_max) {
	Bytes index;
	push_u64(index, CA_FORMAT_INDEX_SIZE);
	push_u64(index, CA_FORMAT_INDEX);
	push_u64(index, CA_FORMAT_SHA512_256 | CA_FORMAT_EXCLUDE_NODUMP);
	push_u64(index, uint64_t(p_min));
	push_u64(index, uint64_t(p_avg));
	push_u64(index, uint64_t(p_max));
	push_u64(index, CA_MAX_UINT64);
	push_u64(index, CA_FORMAT_TABLE);
	for (const CaibxChunk &c : p_chunks) {
		push_u64(index, c.start + c.size);
		index.insert(index.end(), c.id.begin(), c.id.end());
	}
	push_u64(index, 0);
	push_u64(index, 0);
	push_u64(index, CA_FORMAT_INDEX_SIZE);
	push_u64(index, 16 + uint64_t(p_chunks.size()) * 40 + 40);
	push_u64(index, CA_FORMAT_TABLE_TAIL_MARKER);
	return index;
}

bool parse_caibx(const Bytes &p_bytes, std::vector<CaibxChunk> &r_chunks, std::string &r_error) {
	r_chunks.clear();
	Cursor cur{ p_bytes.data(), p_bytes.size(), 0 };
	uint64_t index_size = 0;
	uint64_t index_type = 0;
	if (!cur.u64(index_size) || !cur.u64(index_type)) {
		r_error = "caibx too small for FormatIndex header";
		return false;
	}
	if (index_size != CA_FORMAT_INDEX_SIZE || index_type != CA_FORMAT_INDEX) {
		r_error = "not a caibx: FormatIndex header mismatch";
		return false;
	}
	uint64_t flags = 0;
	uint64_t size_min = 0;
	uint64_t size_avg = 0;
	uint64_t size_max = 0;
	if (!cur.u64(flags) || !cur.u64(size_min) || !cur.u64(size_avg) || !cur.u64(size_max)) {
		r_error = "caibx truncated inside FormatIndex body";
		return false;
	}
	if ((flags & CA_FORMAT_SHA512_256) == 0) {
		r_error = "caibx does not use SHA-512/256 chunk ids";
		return false;
	}
	uint64_t table_size = 0;
	uint64_t table_type = 0;
	if (!cur.u64(table_size) || !cur.u64(table_type) || table_size != CA_MAX_UINT64 ||
			table_type != CA_FORMAT_TABLE) {
		r_error = "FormatTable header mismatch";
		return false;
	}
	uint64_t last = 0;
	for (;;) {
		uint64_t end = 0;
		if (!cur.u64(end)) {
			r_error = "caibx truncated inside chunk table";
			return false;
		}
		if (end == 0) {
			break;
		}
		CaibxChunk c;
		if (!cur.bytes(c.id.data(), CHUNK_ID_BYTES)) {
			r_error = "caibx truncated inside chunk id";
			return false;
		}
		if (end <= last) {
			r_error = "chunk table offsets not increasing";
			return false;
		}
		c.start = last;
		c.size = end - last;
		if (c.size > size_max) {
			r_error = "chunk larger than the index's maximum";
			return false;
		}
		r_chunks.push_back(c);
		last = end;
	}
	uint64_t zero = 0;
	uint64_t index_offset = 0;
	uint64_t tail_size = 0;
	uint64_t marker = 0;
	if (!cur.u64(zero) || !cur.u64(index_offset) || !cur.u64(tail_size) || !cur.u64(marker)) {
		r_error = "caibx truncated inside tail";
		return false;
	}
	if (zero != 0 || marker != CA_FORMAT_TABLE_TAIL_MARKER) {
		r_error = "caibx tail mismatch";
		return false;
	}
	return true;
}

Bytes compress_chunk(const uint8_t *p_data, uint64_t p_len) {
	size_t bound = ZSTD_compressBound(p_len);
	Bytes out(bound);
	size_t written = ZSTD_compress(out.data(), bound, p_data, p_len, 3);
	if (ZSTD_isError(written)) {
		return Bytes();
	}
	out.resize(written);
	return out;
}

bool decompress_and_verify(const Bytes &p_compressed, const ChunkId &p_expected, Bytes &r_out, std::string &r_error) {
	r_out.clear();
	if (p_compressed.empty()) {
		r_error = "compressed chunk is empty";
		return false;
	}
	const uint64_t cap = uint64_t(CHUNK_MAX_BYTES) * 16ULL;
	unsigned long long content = ZSTD_getFrameContentSize(p_compressed.data(), p_compressed.size());
	if (content == ZSTD_CONTENTSIZE_ERROR) {
		r_error = "zstd frame header invalid";
		return false;
	}
	if (content != ZSTD_CONTENTSIZE_UNKNOWN) {
		if (content > cap) {
			r_error = "zstd frame larger than the cap";
			return false;
		}
		r_out.resize(size_t(content));
		size_t n = ZSTD_decompress(r_out.data(), r_out.size(), p_compressed.data(), p_compressed.size());
		if (ZSTD_isError(n) || n != content) {
			r_out.clear();
			r_error = "zstd decompress failed";
			return false;
		}
	} else {
		ZSTD_DCtx *dctx = ZSTD_createDCtx();
		size_t block = ZSTD_DStreamOutSize();
		size_t total = 0;
		ZSTD_inBuffer in{ p_compressed.data(), p_compressed.size(), 0 };
		size_t ret = 1;
		while (in.pos < in.size && ret != 0) {
			if (total + block > cap) {
				ZSTD_freeDCtx(dctx);
				r_out.clear();
				r_error = "zstd stream larger than the cap";
				return false;
			}
			r_out.resize(total + block);
			ZSTD_outBuffer out{ r_out.data() + total, block, 0 };
			ret = ZSTD_decompressStream(dctx, &out, &in);
			if (ZSTD_isError(ret)) {
				ZSTD_freeDCtx(dctx);
				r_out.clear();
				r_error = "zstd stream decompress failed";
				return false;
			}
			total += out.pos;
		}
		ZSTD_freeDCtx(dctx);
		if (ret != 0) {
			r_out.clear();
			r_error = "zstd stream ended mid-frame";
			return false;
		}
		r_out.resize(total);
	}
	if (sha512_256(r_out.data(), r_out.size()) != p_expected) {
		r_out.clear();
		r_error = "chunk SHA-512/256 does not match its id";
		return false;
	}
	return true;
}

Bytes ChunkStore::put(const Bytes &p_data) {
	std::vector<CaibxChunk> table;
	for (const Span &s : chunk_spans(p_data)) {
		CaibxChunk c;
		c.id = sha512_256(p_data.data() + s.start, s.size);
		c.start = s.start;
		c.size = s.size;
		if (!has(c.id)) {
			chunks[c.id] = compress_chunk(p_data.data() + s.start, s.size);
		}
		table.push_back(c);
	}
	return write_caibx(table);
}

const Bytes *ChunkStore::get(const ChunkId &p_id) const {
	std::map<ChunkId, Bytes>::const_iterator it = chunks.find(p_id);
	return it == chunks.end() ? nullptr : &it->second;
}

bool assemble(const Bytes &p_caibx, const ChunkStore &p_store, Bytes &r_out, std::string &r_error) {
	r_out.clear();
	std::vector<CaibxChunk> table;
	if (!parse_caibx(p_caibx, table, r_error)) {
		return false;
	}
	uint64_t total = 0;
	for (const CaibxChunk &c : table) {
		total += c.size;
	}
	r_out.resize(total);
	for (const CaibxChunk &c : table) {
		const Bytes *compressed = p_store.get(c.id);
		if (compressed == nullptr) {
			r_out.clear();
			r_error = "chunk " + hex_from_id(c.id) + " missing from the store";
			return false;
		}
		Bytes plain;
		if (!decompress_and_verify(*compressed, c.id, plain, r_error)) {
			r_out.clear();
			return false;
		}
		if (plain.size() != c.size) {
			r_out.clear();
			r_error = "chunk size disagrees with the index";
			return false;
		}
		std::memcpy(r_out.data() + c.start, plain.data(), plain.size());
	}
	return true;
}

int serve(Transport &p_transport, const ChunkStore &p_store) {
	int answered = 0;
	for (const Packet &p : p_transport.drain(CH_ASSET)) {
		if (p.bytes.size() != 4 + CHUNK_ID_BYTES || get_u32(p.bytes.data()) != CHUNK_REQUEST) {
			continue;
		}
		ChunkId id;
		std::memcpy(id.data(), p.bytes.data() + 4, CHUNK_ID_BYTES);
		const Bytes *compressed = p_store.get(id);
		Bytes reply;
		put_u32(reply, compressed != nullptr ? CHUNK_REPLY : CHUNK_MISSING);
		reply.insert(reply.end(), id.begin(), id.end());
		if (compressed != nullptr) {
			reply.insert(reply.end(), compressed->begin(), compressed->end());
		}
		p_transport.send(p.peer, CH_ASSET, reply.data(), int(reply.size()));
		answered++;
	}
	return answered;
}

bool Fetch::begin(const Bytes &p_caibx, int p_peer, std::string &r_error) {
	index = p_caibx;
	peer = p_peer;
	asked.clear();
	error.clear();
	if (!parse_caibx(index, chunks, r_error)) {
		error = r_error;
		return false;
	}
	return true;
}

bool Fetch::poll(Transport &p_transport) {
	if (!error.empty()) {
		return true;
	}
	for (const Packet &p : p_transport.drain(CH_ASSET)) {
		if (p.bytes.size() < 4 + CHUNK_ID_BYTES) {
			continue;
		}
		uint32_t magic = get_u32(p.bytes.data());
		ChunkId id;
		std::memcpy(id.data(), p.bytes.data() + 4, CHUNK_ID_BYTES);
		if (magic == CHUNK_MISSING) {
			error = "peer lacks chunk " + hex_from_id(id);
			return true;
		}
		if (magic != CHUNK_REPLY) {
			continue;
		}
		Bytes compressed(p.bytes.begin() + 4 + CHUNK_ID_BYTES, p.bytes.end());
		Bytes plain;
		std::string why;
		if (!decompress_and_verify(compressed, id, plain, why)) {
			error = "chunk " + hex_from_id(id) + ": " + why;
			return true;
		}
		store.put_compressed(id, compressed);
	}
	bool complete = true;
	for (const CaibxChunk &c : chunks) {
		if (store.has(c.id)) {
			continue;
		}
		complete = false;
		if (asked.insert(c.id).second) {
			Bytes req;
			put_u32(req, CHUNK_REQUEST);
			req.insert(req.end(), c.id.begin(), c.id.end());
			p_transport.send(peer, CH_ASSET, req.data(), int(req.size()));
		}
	}
	return complete;
}

bool Fetch::result(Bytes &r_out) {
	std::string why;
	if (!assemble(index, store, r_out, why)) {
		error = why;
		return false;
	}
	return true;
}

} // namespace fabric::casync
