// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// The slice of the engine's LocalVector that relativistic_zone.h uses, over std::vector.
#pragma once

#include <cstdint>
#include <vector>

template <typename T>
class LocalVector {
public:
	uint32_t size() const { return uint32_t(data.size()); }
	void push_back(const T &p_value) { data.push_back(p_value); }
	void clear() { data.clear(); }
	T &operator[](uint32_t p_index) { return data[p_index]; }
	const T &operator[](uint32_t p_index) const { return data[p_index]; }

private:
	std::vector<T> data;
};
