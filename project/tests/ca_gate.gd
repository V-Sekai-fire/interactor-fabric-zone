# The CA gate: ca.elf in a Sandbox makes a session root, runs its checks and their controls in the
# guest, and the host confirms what it received is public. Three fresh sandboxes cover the entropy
# sources: the guest's own, the host fallback, and the fallback with nothing fed (which must fail).
#
#   godot --headless --path project --script tests/ca_gate.gd
extends SceneTree

var _failed := 0

func _check(what: String, ok: bool) -> void:
	print(("PASS " if ok else "FAIL ") + what)
	if not ok:
		_failed += 1

func _sandbox():
	var sb = ClassDB.instantiate("Sandbox")
	if sb == null:
		return null
	sb.references_max = 4096
	sb.program = load("res://ca.elf")
	return sb

func _initialize() -> void:
	var sb = _sandbox()
	if sb == null:
		print("FAIL the Sandbox class is not registered (is project/addons/godot_sandbox present?)")
		print("RESULT: FAIL")
		quit(1)
		return
	var now := int(Time.get_unix_time_from_system())
	var opened := str(sb.vmcall("ca_open", now, 86400))
	print("open: ", opened)
	_check("ca_open makes the session root from the guest's own entropy", opened == "ok entropy=os")
	var root := str(sb.vmcall("ca_root"))
	_check("the host receives a root certificate", root.begins_with("-----BEGIN CERTIFICATE-----"))
	_check("and no private key with it", root.find("PRIVATE KEY") < 0)
	_check("control: exporting the root key is refused", int(sb.vmcall("ca_export_root_key")) != 0)
	for line in str(sb.vmcall("ca_selftest", now)).split("\n", false):
		if line.begins_with("PASS ") or line.begins_with("FAIL "):
			_check("guest: " + line.substr(5), line.begins_with("PASS "))
	var bad := str(sb.vmcall("ca_issue", "not a csr", "player-0.zone.fabric.internal", now, 60))
	_check("control: a malformed CSR is refused", bad.begins_with("FAIL"))

	var fed = _sandbox()
	fed.vmcall("ca_entropy_force_host", true)
	print("feed: ", fed.vmcall("ca_entropy_feed", Crypto.new().generate_random_bytes(8192)))
	var fed_open := str(fed.vmcall("ca_open", now, 86400))
	_check("the host fallback makes a root from fed bytes (%s)" % fed_open, fed_open == "ok entropy=host")
	_check("and that root issues and verifies", str(fed.vmcall("ca_selftest", now)).find("FAIL") < 0)

	var starved = _sandbox()
	starved.vmcall("ca_entropy_force_host", true)
	var starved_open := str(starved.vmcall("ca_open", now, 86400))
	_check("control: with the OS source off and nothing fed, no root is made (%s)" % starved_open,
			starved_open.begins_with("FAIL: no entropy"))
	print("RESULT: %s" % ("PASS" if _failed == 0 else "FAIL (%d)" % _failed))
	quit(0 if _failed == 0 else 1)
