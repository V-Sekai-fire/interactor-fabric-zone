// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <vector>

namespace fabric {

// The fabric's four channels. CH_MIGRATION and CH_ASSET need reliable, ordered delivery (a stream):
// a hand-over waits on its intent and ACK, and a chunk reply can run to 256 KiB with no retry.
// CH_INTEREST and CH_PLAYER are datagrams and may drop.
enum Channel : int {
	CH_MIGRATION = 1,
	CH_INTEREST = 2,
	CH_PLAYER = 3,
	CH_ASSET = 4,
};

struct Packet {
	int peer = 0;
	int channel = 0;
	std::vector<uint8_t> bytes;
};

// What a zone, a player client or the asset guest needs from the wire. The
// WebTransport session implements it in the guest; LoopbackNet implements it in memory.
class Transport {
public:
	virtual ~Transport() = default;
	virtual void send(int p_peer, int p_channel, const uint8_t *p_data, int p_size) = 0;
	virtual void broadcast(int p_channel, const uint8_t *p_data, int p_size) = 0;
	virtual std::vector<Packet> drain(int p_channel) = 0;
	virtual bool is_connected(int p_peer) const = 0;
};

// Every endpoint registers by id; a send lands in the target's inbox after
// `delay` delivery rounds, and is dropped when `drop` says so. Deterministic.
class LoopbackNet {
public:
	class Endpoint : public Transport {
	public:
		Endpoint(LoopbackNet &p_net, int p_id) :
				net(p_net), id(p_id) {}
		void send(int p_peer, int p_channel, const uint8_t *p_data, int p_size) override;
		void broadcast(int p_channel, const uint8_t *p_data, int p_size) override;
		std::vector<Packet> drain(int p_channel) override;
		bool is_connected(int p_peer) const override;

	private:
		friend class LoopbackNet;
		LoopbackNet &net;
		int id;
		std::deque<Packet> inbox;
	};

	// Drop predicate over (from, to, channel, sequence number).
	using DropFn = bool (*)(int p_from, int p_to, int p_channel, uint64_t p_seq, void *p_user);

	Endpoint &add(int p_id);
	void set_delay(int p_rounds) { delay = p_rounds; }
	void set_drop(DropFn p_fn, void *p_user) {
		drop = p_fn;
		drop_user = p_user;
	}
	// Moves every packet whose delay has elapsed into its target's inbox.
	void deliver();

private:
	struct InFlight {
		int from;
		int to;
		int due;
		Packet packet;
	};
	std::map<int, Endpoint *> endpoints;
	std::vector<Endpoint *> owned;
	std::vector<InFlight> flight;
	int round = 0;
	int delay = 1;
	uint64_t seq = 0;
	DropFn drop = nullptr;
	void *drop_user = nullptr;

	void post(int p_from, int p_to, int p_channel, const uint8_t *p_data, int p_size);

public:
	~LoopbackNet();
};

} // namespace fabric
