// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "transport.h"

namespace fabric {

void LoopbackNet::Endpoint::send(int p_peer, int p_channel, const uint8_t *p_data, int p_size) {
	net.post(id, p_peer, p_channel, p_data, p_size);
}

void LoopbackNet::Endpoint::broadcast(int p_channel, const uint8_t *p_data, int p_size) {
	for (const std::pair<const int, Endpoint *> &e : net.endpoints) {
		if (e.first != id) {
			net.post(id, e.first, p_channel, p_data, p_size);
		}
	}
}

std::vector<Packet> LoopbackNet::Endpoint::drain(int p_channel) {
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

bool LoopbackNet::Endpoint::is_connected(int p_peer) const {
	return net.endpoints.count(p_peer) > 0;
}

LoopbackNet::Endpoint &LoopbackNet::add(int p_id) {
	Endpoint *e = new Endpoint(*this, p_id);
	endpoints[p_id] = e;
	owned.push_back(e);
	return *e;
}

void LoopbackNet::post(int p_from, int p_to, int p_channel, const uint8_t *p_data, int p_size) {
	uint64_t s = seq++;
	if (drop != nullptr && drop(p_from, p_to, p_channel, s, drop_user)) {
		return;
	}
	InFlight f;
	f.from = p_from;
	f.to = p_to;
	f.due = round + delay;
	f.packet.peer = p_from;
	f.packet.channel = p_channel;
	f.packet.bytes.assign(p_data, p_data + p_size);
	flight.push_back(std::move(f));
}

void LoopbackNet::deliver() {
	round++;
	std::vector<InFlight> later;
	for (InFlight &f : flight) {
		std::map<int, Endpoint *>::iterator it = endpoints.find(f.to);
		if (f.due > round) {
			later.push_back(std::move(f));
		} else if (it != endpoints.end()) {
			it->second->inbox.push_back(std::move(f.packet));
		}
	}
	flight.swap(later);
}

LoopbackNet::~LoopbackNet() {
	for (Endpoint *e : owned) {
		delete e;
	}
}

} // namespace fabric
