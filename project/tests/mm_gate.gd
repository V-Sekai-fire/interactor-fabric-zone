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
const CHECKS := 6
const EPS := 1.0e-4

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

# [name, speed, turn_at, turn_to] as in mm.elf's own run_mm.gd
func scenario(mm, name: String, speed: float, turn_at: float, turn_to: float, control: bool) -> void:
	var z = sandbox("res://zone.elf")
	z.vmcall("zone_plant_zero_velocity", control)
	z.vmcall("zone_open", 0, 1, 64, 60)
	mm.vmcall("mm_reset", 0.0, 0.0, 0.0, 0)
	var dt := 1.0 / 60.0
	var pos: Array = []
	var boxes: Array = []
	var vels: Array = []
	for i in 60 * 8:
		var heading := turn_to if (turn_at >= 0.0 and float(i) * dt >= turn_at) else 0.0
		var out: PackedFloat32Array = mm.vmcall("mm_step", dt, sin(heading) * speed, cos(heading) * speed, NAN, 0, 0)
		var x := float(out[2])
		var zz := float(out[3])
		z.vmcall("zone_player_pose", 1, x, 0.0, zz)
		z.vmcall("zone_tick")
		pos.append(Vector2(x, zz))
		var g: PackedByteArray = z.vmcall("zone_player_ghost", 1)
		vels.append(Vector2.ZERO if g.size() < 80 else Vector2(g.decode_double(0), g.decode_double(16)))
		boxes.append([] if g.size() < 80 else [g.decode_double(24), g.decode_double(40), g.decode_double(48), g.decode_double(64), int(g.decode_double(72))])
	var vbad := 0
	var vmax := 0.0
	for i in range(2, pos.size()):
		var want: Vector2 = (pos[i] - pos[i - 1]).limit_length(0.5)
		vmax = max(vmax, want.length())
		if (vels[i] - want).length() > 1.0e-6:
			vbad += 1
	var ext: Array = boxes[boxes.size() - 1]
	print("%s: %d of %d ticks hold a velocity other than mm.elf's (max %.4f m/tick); last box x %.3f..%.3f, horizon %d" % [name, vbad, pos.size() - 2, vmax, ext[0], ext[2], ext[4]])
	check("the zone holds the velocity mm.elf's positions imply (%s)" % name, vbad == 0 and (vmax > 0.01 or name == "stand"))
	var held := 0
	var outside := 0
	# Skip the first ticks: the zone has seen too few poses to hold a velocity yet.
	for i in range(4, pos.size() - 1):
		var b: Array = boxes[i]
		if b.is_empty():
			continue
		held += 1
		for k in range(1, min(int(b[4]), pos.size() - 1 - i) + 1):
			var p: Vector2 = pos[i + k]
			if p.x < b[0] - EPS or p.x > b[2] + EPS or p.y < b[1] - EPS or p.y > b[3] + EPS:
				outside += 1
				break
	print("%s: %d boxes held, %d leave their box inside the horizon" % [name, held, outside])
	check("mm.elf's later positions stay inside the zone's ghost box (%s)" % name, held > 100 and outside == 0)

func _process(_d: float) -> bool:
	var mm = sandbox("res://mm.elf")
	load_clips(mm)
	var control: bool = arg("control") == "zero_velocity"
	scenario(mm, "walk", 1.3, -1.0, 0.0, control)
	scenario(mm, "run", 3.5, -1.0, 0.0, control)
	scenario(mm, "turn", 1.3, 3.0, PI / 2, control)
	if checked != CHECKS:
		print("FAIL made %d checks, expected %d" % [checked, CHECKS])
		fails += 1
	print("RESULT: %s" % ("PASS" if fails == 0 else "FAIL"))
	quit(0 if fails == 0 else 1)
	return true
