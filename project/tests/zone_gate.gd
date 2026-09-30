# zone.elf and asset.elf in the sandbox, headless: two zones and two asset guests, their frames
# relayed on the host. Prints one line per check and RESULT: PASS or FAIL.
#   godot --headless --path project --script tests/zone_gate.gd
extends SceneTree

var fails := 0
var flushes := 0

func check(what: String, ok: bool) -> void:
	print("%s %s" % ["PASS" if ok else "FAIL", what])
	if not ok:
		fails += 1

func sandbox(elf: String):
	var sb = ClassDB.instantiate("Sandbox")
	sb.allocations_max = 1000000
	sb.program = load(elf)
	return sb

func frames(buf: PackedByteArray) -> Array:
	var out := []
	var off := 0
	while off + 12 <= buf.size():
		var peer := buf.decode_s32(off)
		var ch := buf.decode_u32(off + 4)
		var n := buf.decode_u32(off + 8)
		out.append([peer, ch, buf.slice(off + 12, off + 12 + n)])
		off += 12 + n
	return out

func _initialize() -> void:
	var z := [sandbox("res://zone.elf"), sandbox("res://zone.elf")]
	for i in 2:
		print(z[i].vmcall("zone_open", i, 2, 64, 60))
		z[i].vmcall("zone_connect", 1 - i, true)
	print(z[1].vmcall("zone_journal_open", PackedByteArray()))
	var image := PackedByteArray()
	var gid := 3000001
	z[1].vmcall("zone_spawn", gid, 5.0, 0.0, 0.0, PackedByteArray())
	var worst := 0
	var lost := 0
	var ghost_seen := false
	var pending := [[], []]
	for t in 60:
		if t == 10:
			z[1].vmcall("zone_handover", gid, 0)
		for i in 2:
			for f in pending[i]:
				z[i].vmcall("zone_packet_in", f[0], f[1], f[2])
			pending[i] = []
		var out := [z[0].vmcall("zone_tick"), z[1].vmcall("zone_tick")]
		var taken: PackedByteArray = z[1].vmcall("zone_journal_take")
		if taken.size() > 0:
			flushes += 1
			image = taken
		for i in 2:
			for f in frames(out[i]):
				if f[0] == -1 or f[0] == 1 - i:
					pending[1 - i].append([i, f[1], f[2]])
		var s0: int = z[0].vmcall("zone_state", gid)
		var s1: int = z[1].vmcall("zone_state", gid)
		worst = max(worst, int(s0 == 1) + int(s1 == 1))
		lost += int(s0 == 0 and s1 == 0)
		if t == 8:
			ghost_seen = z[0].vmcall("zone_ghosts").size() > 0
	print(z[0].vmcall("zone_status"))
	print(z[1].vmcall("zone_status"))
	check("the garment's ghost materializes in the players' zone before the hand-over", ghost_seen)
	check("never more than one owner in a tick (worst %d)" % worst, worst == 1)
	check("never a tick with no holder (%d)" % lost, lost == 0)
	check("the players' zone owns the garment after the hand-over", z[0].vmcall("zone_state", gid) == 1 and z[1].vmcall("zone_state", gid) == 0)
	check("the worker's journal flushed to the host (%d flushes, %d bytes)" % [flushes, image.size()], flushes >= 2 and image.size() > 0)
	var z2 = sandbox("res://zone.elf")
	z2.vmcall("zone_open", 1, 2, 64, 60)
	print(z2.vmcall("zone_journal_open", image))

	var a := [sandbox("res://asset.elf"), sandbox("res://asset.elf")]
	var data := PackedByteArray()
	data.resize(300000)
	var x := 12345
	for i in data.size():
		x = (x * 1103515245 + 12345) & 0x7fffffff
		data[i] = (x >> 16) & (0xff if (i % 3000) < 1500 else 0x0f)
	var index: PackedByteArray = a[0].vmcall("asset_put", data)
	print(a[0].vmcall("asset_status"))
	print(a[1].vmcall("asset_fetch_begin", index, 0))
	var state := 0
	for r in 20:
		state = a[1].vmcall("asset_fetch_poll")
		if state != 0:
			break
		for f in frames(a[1].vmcall("asset_frames")):
			a[0].vmcall("asset_packet_in", 1, f[1], f[2])
		for f in frames(a[0].vmcall("asset_serve")):
			a[1].vmcall("asset_packet_in", 0, f[1], f[2])
	var got: PackedByteArray = a[1].vmcall("asset_fetch_result")
	check("an asset fetched chunk by chunk equals what was stored (%d bytes, state %d)" % [got.size(), state], state == 1 and got == data)
	print("RESULT: %s" % ["PASS" if fails == 0 else "FAIL (%d)" % fails])
	quit(0 if fails == 0 else 1)
