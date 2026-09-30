# The transport gate: two quic_peer.elf guests handshake QUIC with mutual TLS over loopback UDP, open
# a WebTransport session on it, and trade a datagram each way; no relayed datagram may hold those bytes
# in the clear. Controls, each a fresh pair of peers, must fail: a client certificate from another CA,
# a client that trusts another root, an expired client certificate, the wrong server name, and a
# datagram with one byte flipped in transit.
# The host only relays datagrams through PacketPeerUDP and passes the time in; each peer's key is
# made in its own guest, and ca.elf issues both certificates from the session root. Two controls,
# each a fresh pair of peers, must fail: a client whose certificate comes from another CA, and a
# client that trusts another root.
#
#   godot --headless --path project --script tests/quic_gate.gd
extends SceneTree

const LOOPBACK := 0x7f000001
const SERVER_NAME := "zone-0.zone.fabric.internal"
const CLIENT_NAME := "player-0.zone.fabric.internal"

var _failed := 0
var _relay: Array = []
var _plaintext_seen := false
var _tamper := false

func _check(what: String, ok: bool) -> void:
	print(("PASS " if ok else "FAIL ") + what)
	if not ok:
		_failed += 1

func _guest(elf: String):
	var sb = ClassDB.instantiate("Sandbox")
	if sb == null:
		return null
	sb.references_max = 4096
	sb.program = load(elf)
	return sb

func _authority():
	var ca = _guest("res://ca.elf")
	ca.vmcall("ca_open", int(Time.get_unix_time_from_system()), 86400)
	return ca

func _peer(is_server: bool, name: String, issuer, trusted_root: String, start_ago := 60, seconds := 3600) -> Dictionary:
	var peer = _guest("res://quic_peer.elf")
	var csr := str(peer.vmcall("quic_make_key", name))
	var now := int(Time.get_unix_time_from_system())
	var cert := str(issuer.vmcall("ca_issue", csr, name, now - start_ago, seconds))
	var opened := str(peer.vmcall("quic_open", is_server, cert, trusted_root, Time.get_ticks_usec()))
	return {"sandbox": peer, "opened": opened, "cert": cert}

func _pump(peer, udp: PacketPeerUDP) -> void:
	for i in 20:
		var d: Dictionary = peer.vmcall("quic_prepare", Time.get_ticks_usec())
		var bytes: PackedByteArray = d["bytes"]
		if bytes.is_empty():
			return
		if bytes.hex_encode().find("68656c6c6f") >= 0:
			_plaintext_seen = true
		if _tamper:
			bytes[bytes.size() - 1] ^= 1
		udp.set_dest_address("127.0.0.1", int(d["port"]))
		udp.put_packet(bytes)

func _drain(peer, udp: PacketPeerUDP, own_port: int) -> void:
	while udp.get_available_packet_count() > 0:
		var bytes := udp.get_packet()
		peer.vmcall("quic_incoming", bytes, LOOPBACK, udp.get_packet_port(), LOOPBACK, own_port, Time.get_ticks_usec())

# Returns [client state, server state, client error, server error] after at most two seconds.
func _handshake(server, client, label: String, server_name := SERVER_NAME) -> Array:
	var su := PacketPeerUDP.new()
	var cu := PacketPeerUDP.new()
	su.bind(0, "127.0.0.1")
	cu.bind(0, "127.0.0.1")
	var sp := su.get_local_port()
	var cp := cu.get_local_port()
	client.vmcall("quic_connect", LOOPBACK, sp, server_name, Time.get_ticks_usec())
	var deadline := Time.get_ticks_msec() + 2000
	while Time.get_ticks_msec() < deadline:
		_pump(client, cu)
		_pump(server, su)
		OS.delay_msec(2)
		_drain(server, su, sp)
		_drain(client, cu, cp)
		var cs := int(client.vmcall("quic_state"))
		var ss := int(server.vmcall("quic_state"))
		if (cs == 2 and ss == 2) or cs == 3 or ss == 3:
			break
	var r := [int(client.vmcall("quic_state")), int(server.vmcall("quic_state")),
			int(client.vmcall("quic_error")), int(server.vmcall("quic_error"))]
	print("%s: client=%d server=%d client_error=0x%x server_error=0x%x" % [label, r[0], r[1], r[2], r[3]])
	_relay = [su, cu, sp, cp]
	return r

# Keeps relaying until the session is up, then sends "hello zone" up and waits for "hello player" back.
func _session(server, client, tamper := false) -> Array:
	var su: PacketPeerUDP = _relay[0]
	var cu: PacketPeerUDP = _relay[1]
	var sp: int = _relay[2]
	var cp: int = _relay[3]
	var up := ""
	var down := ""
	var sent := false
	var deadline := Time.get_ticks_msec() + (1500 if tamper else 3000)
	while Time.get_ticks_msec() < deadline and down == "":
		if not sent and int(client.vmcall("quic_session")) == 1 and int(server.vmcall("quic_session")) == 1:
			sent = int(client.vmcall("quic_send_datagram", "hello zone".to_utf8_buffer())) == 0
		_tamper = tamper and sent
		_pump(client, cu)
		_tamper = false
		_pump(server, su)
		OS.delay_msec(2)
		_drain(server, su, sp)
		_drain(client, cu, cp)
		var got: PackedByteArray = server.vmcall("quic_take_datagram")
		if not got.is_empty():
			up = got.get_string_from_utf8()
			server.vmcall("quic_send_datagram", "hello player".to_utf8_buffer())
		var back: PackedByteArray = client.vmcall("quic_take_datagram")
		if not back.is_empty():
			down = back.get_string_from_utf8()
	return [int(client.vmcall("quic_session")), int(server.vmcall("quic_session")), up, down]

func _initialize() -> void:

	if ClassDB.instantiate("Sandbox") == null:
		print("FAIL the Sandbox class is not registered (is project/addons/godot_sandbox present?)")
		print("RESULT: FAIL")
		quit(1)
		return
	var ca = _authority()
	var other = _authority()
	var root := str(ca.vmcall("ca_root"))
	var other_root := str(other.vmcall("ca_root"))

	var server := _peer(true, SERVER_NAME, ca, root)
	var client := _peer(false, CLIENT_NAME, ca, root)
	_check("both peers open with certificates from the session root", server.opened == "ok" and client.opened == "ok")
	var r := _handshake(server.sandbox, client.sandbox, "session root")
	_check("the handshake completes over loopback UDP, both ends ready", r[0] == 2 and r[1] == 2)
	var wt := _session(server.sandbox, client.sandbox)
	_check("the WebTransport session is up at both ends (client %d, server %d)" % [wt[0], wt[1]], wt[0] == 1 and wt[1] == 1)
	_check("a datagram crosses each way intact (%s / %s)" % [wt[2], wt[3]], wt[2] == "hello zone" and wt[3] == "hello player")
	_check("no relayed datagram holds the datagrams' bytes in the clear", not _plaintext_seen)

	var s4 := _peer(true, SERVER_NAME, ca, root)
	var c4 := _peer(false, CLIENT_NAME, ca, root)
	_handshake(s4.sandbox, c4.sandbox, "control: tampered datagram")
	var bent := _session(s4.sandbox, c4.sandbox, true)
	_check("control: a datagram with one byte flipped in transit does not arrive (session %d/%d, got '%s')" % [bent[0], bent[1], bent[2]],
			bent[0] == 1 and bent[1] == 1 and bent[2] == "")

	var s5 := _peer(true, SERVER_NAME, ca, root)
	var stale := _peer(false, CLIENT_NAME, ca, root, 120, 60)
	var r5 := _handshake(s5.sandbox, stale.sandbox, "control: expired client certificate")
	_check("control: an expired client certificate ends the handshake", r5[0] != 2 or r5[1] != 2)

	var s6 := _peer(true, SERVER_NAME, ca, root)
	var c6 := _peer(false, CLIENT_NAME, ca, root)
	var r6 := _handshake(s6.sandbox, c6.sandbox, "control: wrong server name", "zone-1.zone.fabric.internal")
	_check("control: the wrong server name is refused", r6[0] != 2)

	var s2 := _peer(true, SERVER_NAME, ca, root)
	var foreign := _peer(false, CLIENT_NAME, other, root)
	var r2 := _handshake(s2.sandbox, foreign.sandbox, "control: client certificate from another CA")
	_check("control: a client certificate from another CA is refused", r2[0] != 2 or r2[1] != 2)

	var s3 := _peer(true, SERVER_NAME, ca, root)
	var misled := _peer(false, CLIENT_NAME, ca, other_root)
	var r3 := _handshake(s3.sandbox, misled.sandbox, "control: client trusts another root")
	_check("control: a client that trusts another root refuses the zone", r3[0] != 2)
	print("RESULT: %s" % ("PASS" if _failed == 0 else "FAIL (%d)" % _failed))
	quit(0 if _failed == 0 else 1)
