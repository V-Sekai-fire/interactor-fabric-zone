// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// A Transport whose far side is the host: packets come in one call at a time, and go out as
// frames [peer i32][channel u32][length u32][bytes], peer -1 meaning broadcast.
#pragma once

#include "transport.h"

#include <set>

namespace fabric {

class FrameTransport : public Transport {
public:
	static constexpr int BROADCAST = -1;

	void send(int p_peer, int p_channel, const uint8_t *p_data, int p_size) override;
	void broadcast(int p_channel, const uint8_t *p_data, int p_size) override;
	std::vector<Packet> drain(int p_channel) override;
	bool is_connected(int p_peer) const override { return connected.count(p_peer) > 0; }

	void receive(int p_peer, int p_channel, const uint8_t *p_data, int p_size);
	void set_connected(int p_peer, bool p_connected);
	// Takes every queued frame, concatenated.
	std::vector<uint8_t> take_frames();

	static bool next_frame(const std::vector<uint8_t> &p_frames, size_t &r_offset, int &r_peer, int &r_channel,
			std::vector<uint8_t> &r_bytes);

private:
	std::deque<Packet> inbox;
	std::vector<uint8_t> outbox;
	std::set<int> connected;
};

} // namespace fabric
