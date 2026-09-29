// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "frame_transport.h"

#include <cstring>

namespace fabric {

namespace {

void put32(std::vector<uint8_t> &r_out, uint32_t p_v) {
	for (int b = 0; b < 4; b++) {
		r_out.push_back(uint8_t((p_v >> (b * 8)) & 0xFF));
	}
}

uint32_t get32(const uint8_t *p_data) {
	return uint32_t(p_data[0]) | (uint32_t(p_data[1]) << 8) | (uint32_t(p_data[2]) << 16) |
			(uint32_t(p_data[3]) << 24);
}

} // namespace

void FrameTransport::send(int p_peer, int p_channel, const uint8_t *p_data, int p_size) {
	put32(outbox, uint32_t(p_peer));
	put32(outbox, uint32_t(p_channel));
	put32(outbox, uint32_t(p_size));
	outbox.insert(outbox.end(), p_data, p_data + p_size);
}

void FrameTransport::broadcast(int p_channel, const uint8_t *p_data, int p_size) {
	send(BROADCAST, p_channel, p_data, p_size);
}

std::vector<Packet> FrameTransport::drain(int p_channel) {
	std::vector<Packet> out;
	std::deque<Packet> keep;
	for (Packet &p : inbox) {
		if (p.channel == p_channel) {
			out.push_back(std::move(p));
		} else {
			keep.push_back(std::move(p));
		}
	}
	inbox.swap(keep);
	return out;
}

void FrameTransport::receive(int p_peer, int p_channel, const uint8_t *p_data, int p_size) {
	Packet p;
	p.peer = p_peer;
	p.channel = p_channel;
	p.bytes.assign(p_data, p_data + p_size);
	inbox.push_back(std::move(p));
}

void FrameTransport::set_connected(int p_peer, bool p_connected) {
	if (p_connected) {
		connected.insert(p_peer);
	} else {
		connected.erase(p_peer);
	}
}

std::vector<uint8_t> FrameTransport::take_frames() {
	std::vector<uint8_t> out;
	out.swap(outbox);
	return out;
}

bool FrameTransport::next_frame(const std::vector<uint8_t> &p_frames, size_t &r_offset, int &r_peer, int &r_channel,
		std::vector<uint8_t> &r_bytes) {
	if (r_offset + 12 > p_frames.size()) {
		return false;
	}
	const uint8_t *h = p_frames.data() + r_offset;
	uint32_t len = get32(h + 8);
	if (r_offset + 12 + len > p_frames.size()) {
		return false;
	}
	r_peer = int(get32(h));
	r_channel = int(get32(h + 4));
	r_bytes.assign(h + 12, h + 12 + len);
	r_offset += 12 + len;
	return true;
}

} // namespace fabric
