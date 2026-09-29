// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
// A player's humanoid pose on CH_PLAYER: the root, then each present bone's rotation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fabric::pose {

// The engine's humanoid bone order (55 bones), spelled as avatar .fbx.meta files spell them.
constexpr int BONE_COUNT = 55;
extern const char *const BONE_NAMES[BONE_COUNT];
int bone_index(const std::string &p_name);

constexpr uint32_t POSE_MAGIC = 0x45534F50u; // 'POSE'
constexpr int QUAT_SCALE = 32767;

struct Pose {
	uint32_t player_id = 0;
	uint32_t tick = 0;
	uint64_t mask = 0; // bit i set: bone i present
	double root[3] = { 0.0, 0.0, 0.0 };
	float root_rot[4] = { 0.0f, 0.0f, 0.0f, 1.0f }; // x, y, z, w
	float rot[BONE_COUNT][4] = {};
};

// [POSE][player][tick][mask u64][root 3 x f64][root_rot 4 x i16][present bones 4 x i16 each].
std::vector<uint8_t> encode(const Pose &p_pose);
bool decode(const uint8_t *p_data, int p_size, Pose &r_pose);
int encoded_size(uint64_t p_mask);

} // namespace fabric::pose
