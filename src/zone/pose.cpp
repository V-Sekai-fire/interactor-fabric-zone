// SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
// SPDX-License-Identifier: MIT
#include "pose.h"

#include <cmath>
#include <cstring>

namespace fabric::pose {

const char *const BONE_NAMES[BONE_COUNT] = {
	"Hips",
	"LeftUpperLeg",
	"RightUpperLeg",
	"LeftLowerLeg",
	"RightLowerLeg",
	"LeftFoot",
	"RightFoot",
	"Spine",
	"Chest",
	"Neck",
	"Head",
	"LeftShoulder",
	"RightShoulder",
	"LeftUpperArm",
	"RightUpperArm",
	"LeftLowerArm",
	"RightLowerArm",
	"LeftHand",
	"RightHand",
	"LeftToes",
	"RightToes",
	"LeftEye",
	"RightEye",
	"Jaw",
	"Left Thumb Proximal",
	"Left Thumb Intermediate",
	"Left Thumb Distal",
	"Left Index Proximal",
	"Left Index Intermediate",
	"Left Index Distal",
	"Left Middle Proximal",
	"Left Middle Intermediate",
	"Left Middle Distal",
	"Left Ring Proximal",
	"Left Ring Intermediate",
	"Left Ring Distal",
	"Left Little Proximal",
	"Left Little Intermediate",
	"Left Little Distal",
	"Right Thumb Proximal",
	"Right Thumb Intermediate",
	"Right Thumb Distal",
	"Right Index Proximal",
	"Right Index Intermediate",
	"Right Index Distal",
	"Right Middle Proximal",
	"Right Middle Intermediate",
	"Right Middle Distal",
	"Right Ring Proximal",
	"Right Ring Intermediate",
	"Right Ring Distal",
	"Right Little Proximal",
	"Right Little Intermediate",
	"Right Little Distal",
	"UpperChest",
};

namespace {

void put(std::vector<uint8_t> &r_out, const void *p_data, size_t p_n) {
	const uint8_t *b = static_cast<const uint8_t *>(p_data);
	r_out.insert(r_out.end(), b, b + p_n);
}

// w >= 0 so q and -q (the same rotation) encode the same.
void put_quat(std::vector<uint8_t> &r_out, const float p_q[4]) {
	float sign = p_q[3] < 0.0f ? -1.0f : 1.0f;
	for (int k = 0; k < 4; k++) {
		float c = p_q[k] * sign;
		c = c < -1.0f ? -1.0f : (c > 1.0f ? 1.0f : c);
		int16_t v = int16_t(std::lround(c * float(QUAT_SCALE)));
		put(r_out, &v, 2);
	}
}

void get_quat(const uint8_t *p_data, float r_q[4]) {
	for (int k = 0; k < 4; k++) {
		int16_t v;
		std::memcpy(&v, p_data + k * 2, 2);
		r_q[k] = float(v) / float(QUAT_SCALE);
	}
}

int popcount64(uint64_t p_v) {
	int n = 0;
	while (p_v != 0) {
		p_v &= p_v - 1;
		n++;
	}
	return n;
}

} // namespace

int bone_index(const std::string &p_name) {
	for (int i = 0; i < BONE_COUNT; i++) {
		if (p_name == BONE_NAMES[i]) {
			return i;
		}
	}
	return -1;
}

int encoded_size(uint64_t p_mask) {
	return 4 + 4 + 4 + 8 + 24 + 8 + popcount64(p_mask & ((uint64_t(1) << BONE_COUNT) - 1)) * 8;
}

std::vector<uint8_t> encode(const Pose &p_pose) {
	std::vector<uint8_t> out;
	uint64_t mask = p_pose.mask & ((uint64_t(1) << BONE_COUNT) - 1);
	out.reserve(encoded_size(mask));
	put(out, &POSE_MAGIC, 4);
	put(out, &p_pose.player_id, 4);
	put(out, &p_pose.tick, 4);
	put(out, &mask, 8);
	put(out, p_pose.root, 24);
	put_quat(out, p_pose.root_rot);
	for (int i = 0; i < BONE_COUNT; i++) {
		if ((mask >> i) & 1u) {
			put_quat(out, p_pose.rot[i]);
		}
	}
	return out;
}

bool decode(const uint8_t *p_data, int p_size, Pose &r_pose) {
	if (p_size < encoded_size(0)) {
		return false;
	}
	uint32_t magic;
	std::memcpy(&magic, p_data, 4);
	if (magic != POSE_MAGIC) {
		return false;
	}
	uint64_t mask;
	std::memcpy(&mask, p_data + 12, 8);
	if (mask >> BONE_COUNT != 0 || p_size != encoded_size(mask)) {
		return false;
	}
	r_pose = Pose();
	std::memcpy(&r_pose.player_id, p_data + 4, 4);
	std::memcpy(&r_pose.tick, p_data + 8, 4);
	r_pose.mask = mask;
	std::memcpy(r_pose.root, p_data + 20, 24);
	get_quat(p_data + 44, r_pose.root_rot);
	const uint8_t *cur = p_data + 52;
	for (int i = 0; i < BONE_COUNT; i++) {
		if ((mask >> i) & 1u) {
			get_quat(cur, r_pose.rot[i]);
			cur += 8;
		}
	}
	return true;
}

} // namespace fabric::pose
