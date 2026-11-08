# mm.elf drives a player into zone.elf, both in the sandbox: for each scenario, one mm_step per zone
# tick gives the player's root, and every position within the ghost box's horizon must lie inside the
# box the zone holds for that player. Prints one line per check and RESULT: PASS or FAIL.
#   godot --headless --path project --script tests/mm_gate.gd -- --clips=<dir>[:<dir>] [--control=zero_velocity]
#
# Per scenario two checks: the zone holds the velocity mm.elf's own positions imply (one tick apart),
# and later positions stay inside the ghost box. Zero velocity gives a loose box that still contains
# the player, so only the velocity check catches the pre-#505 zone.
# --control=zero_velocity plants that zone (players hold zero velocity): the gate must exit non-zero.
extends SceneTree

var fails := 0
var checked := 0
# walk, run, turn: a script error skips the rest without a FAIL line, so fewer checks fail.
const CHECKS := 7
# Tolerances, not copies of zone values: the ghost box is integer micrometres (1e-6 m), and the held
# velocity is derived in doubles from f32 positions.
const BOX_EPS := 1.0e-4
const VELOCITY_TOL := 1.0e-6
# The zone holds a velocity from its second pose, and a settled box from its fourth tick.
const VELOCITY_WARMUP := 2
const BOX_WARMUP := 4
# A scenario must move the player, or its checks hold trivially.
const MIN_MOVE := 0.01
const SECONDS := 8
const PLAYER := 1
# zone_limits() and zone_player_ghost() return doubles by index.
const L_VMAX := 0
const L_HZ := 2
const G_VX := 0
const G_VZ := 2
const G_MIN_X := 3
const G_MIN_Z := 5
const G_MAX_X := 6
const G_MAX_Z := 8
const G_HORIZON := 9
const G_COUNT := 10
# Speeds come from mm.elf, not from this file. Walk is the stand mode's median moving speed
# (mm_modes: "name poses median"). Run is a high quantile of the moving clips' p90 speeds, the
# speed each clip sustains (mm_clips: "name frames seconds speed dx dz median p90"). A clip's
# median is not used: it includes the starts and stops, so even run clips read slow. The
# quantile is a choice about this test: the fastest clips, not the single fastest.
const RUN_QUANTILE := 0.9
# A clip counts as moving above this speed (m/s), as mm_modes counts a moving pose.
const MOVING_MIN := 0.2
# Run must clearly outpace walk, or the run case would test walking twice.
const RUN_OVER_WALK_MIN := 1.5
# mm_step arguments: mode 0 is stand (mm_core's Mode enum), no jump, and no turn is a negative time.
const STAND_MODE := 0
const NO_JUMP := 0
const NO_TURN := -1.0
# The turn case: at this time the heading changes to this angle.
const TURN_AT_S := 3.0
const TURN_TO := PI / 2

func check(what: String, ok: bool) -> void:
	checked += 1
	print("%s %s" % ["PASS" if ok else "FAIL", what])
	if not ok:
		fails += 1

func arg(n: String) -> String:
	for a in OS.get_cmdline_user_args():
		if a.begins_with("--%s=" % n):
			return a.trim_prefix("--%s=" % n)
	return ""

func sandbox(elf: String):
	var sb = ClassDB.instantiate("Sandbox")
	sb.allocations_max = 1000000
	sb.references_max = 4096
	sb.memory_max = 512
	sb.execution_timeout = 60000
	sb.program = load(elf)
	return sb

func load_clips(mm) -> void:
	for dir in arg("clips").split(":", false):
		var keys := DirAccess.get_directories_at(dir)
		keys.sort()
		for k in keys:
			var d: String = dir.path_join(k)
			var names := PackedStringArray()
			var fps := 30.0
			for line in FileAccess.get_file_as_string(d.path_join("skeleton.txt")).split("\n", false):
				if line.begins_with("frames "):
					fps = float(line.split(" ")[3])
				elif not line.begins_with("model ") and not line.begins_with("prompt "):
					names.append(line)
			var parents := PackedInt32Array()
			for p in FileAccess.get_file_as_string(d.path_join("parents.txt")).split("\n", false):
				parents.append(int(p))
			var xf := FileAccess.get_file_as_bytes(d.path_join("transforms.f32")).to_float32_array()
			var loop := 1 if FileAccess.file_exists(d.path_join("loop.txt")) else 0
			mm.vmcall("mm_add_clip", k, "\n".join(names), parents, xf, fps, loop)
	print(mm.vmcall("mm_bake"))

# [walk, run] in m/s, derived from the baked database; [] when it has no moving stand poses or clips.
func speeds(mm) -> Array:
	var walk := 0.0
	for line in str(mm.vmcall("mm_modes")).split("\n", false):
		var w := line.split(" ")
		if w[0] == "stand":
			walk = float(w[2])
	var peaks: Array = []
	for line in str(mm.vmcall("mm_clips")).split("\n", false):
		var w := line.split(" ")
		var med := float(w[w.size() - 2])
		if med > MOVING_MIN:
			peaks.append(float(w[w.size() - 1]))
	if walk <= 0.0 or peaks.is_empty():
		return []
	peaks.sort()
	return [walk, peaks[int(RUN_QUANTILE * (peaks.size() - 1))]]

# [name, speed, turn_at, turn_to] as in mm.elf's own run_mm.gd
func scenario(mm, name: String, speed: float, turn_at: float, turn_to: float, control: bool) -> void:
	var z = sandbox("res://zone.elf")
	z.vmcall("zone_plant_zero_velocity", control)
	z.vmcall("zone_open", 0, 1, 0, 0) # the zone's own capacity and rate
	var limits: PackedFloat64Array = z.vmcall("zone_limits")
	var v_max: float = limits[L_VMAX]
	var hz: float = limits[L_HZ]
	mm.vmcall("mm_reset", 0.0, 0.0, 0.0, 0)
	var dt := 1.0 / hz
	var pos: Array = []
	var boxes: Array = []
	var vels: Array = []
	for i in int(hz) * SECONDS:
		var heading := turn_to if (turn_at != NO_TURN and float(i) * dt >= turn_at) else 0.0
		var out: PackedFloat32Array = mm.vmcall("mm_step", dt, sin(heading) * speed, cos(heading) * speed, NAN, STAND_MODE, NO_JUMP)
		var x := float(out[2])
		var zz := float(out[3])
		z.vmcall("zone_player_pose", PLAYER, x, 0.0, zz)
		z.vmcall("zone_tick")
		pos.append(Vector2(x, zz))
		var g: PackedFloat64Array = z.vmcall("zone_player_ghost", PLAYER)
		var have := g.size() >= G_COUNT
		vels.append(Vector2(g[G_VX], g[G_VZ]) if have else Vector2.ZERO)
		boxes.append([g[G_MIN_X], g[G_MIN_Z], g[G_MAX_X], g[G_MAX_Z], int(g[G_HORIZON])] if have else [])
	var vbad := 0
	var vmax := 0.0
	for i in range(VELOCITY_WARMUP, pos.size()):
		var d: Vector2 = pos[i] - pos[i - 1]
		var want := Vector2(clampf(d.x, -v_max, v_max), clampf(d.y, -v_max, v_max))
		vmax = max(vmax, want.length())
		if (vels[i] - want).length() > VELOCITY_TOL:
			vbad += 1
	var ext: Array = boxes[boxes.size() - 1]
	print("%s: %d of %d ticks hold a velocity other than mm.elf's (max %.4f m/tick); last box x %.3f..%.3f, horizon %d" % [name, vbad, pos.size() - VELOCITY_WARMUP, vmax, ext[0], ext[2], ext[4]])
	check("the zone holds the velocity mm.elf's positions imply (%s)" % name, vbad == 0 and vmax > MIN_MOVE)
	var held := 0
	var outside := 0
	# Skip the first ticks: the zone has seen too few poses to hold a velocity yet.
	for i in range(BOX_WARMUP, pos.size() - 1):
		var b: Array = boxes[i]
		if b.is_empty():
			continue
		held += 1
		for k in range(1, min(int(b[4]), pos.size() - 1 - i) + 1):
			var p: Vector2 = pos[i + k]
			if p.x < b[0] - BOX_EPS or p.x > b[2] + BOX_EPS or p.y < b[1] - BOX_EPS or p.y > b[3] + BOX_EPS:
				outside += 1
				break
	print("%s: %d boxes held, %d leave their box inside the horizon" % [name, held, outside])
	check("mm.elf's later positions stay inside the zone's ghost box (%s)" % name, held == pos.size() - 1 - BOX_WARMUP and outside == 0)

func _process(_d: float) -> bool:
	var mm = sandbox("res://mm.elf")
	load_clips(mm)
	var control: bool = arg("control") == "zero_velocity"
	var sp := speeds(mm)
	check("mm.elf has moving stand poses and clips to take speeds from", not sp.is_empty())
	if sp.is_empty():
		print("RESULT: FAIL")
		quit(1)
		return true
	var walk: float = sp[0]
	var run: float = sp[1]
	print("speeds from mm.elf: walk %.3f m/s (stand median), run %.3f m/s (clip p90 quantile %.2f)" % [walk, run, RUN_QUANTILE])
	if run <= walk * RUN_OVER_WALK_MIN:
		print("FAIL run %.3f m/s is not %.1fx walk %.3f m/s" % [run, RUN_OVER_WALK_MIN, walk])
		fails += 1
	scenario(mm, "walk", walk, NO_TURN, 0.0, control)
	scenario(mm, "run", run, NO_TURN, 0.0, control)
	scenario(mm, "turn", walk, TURN_AT_S, TURN_TO, control)
	if checked != CHECKS:
		print("FAIL made %d checks, expected %d" % [checked, CHECKS])
		fails += 1
	print("RESULT: %s" % ("PASS" if fails == 0 else "FAIL"))
	quit(0 if fails == 0 else 1)
	return true
