-- SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
-- SPDX-License-Identifier: MIT
import PlausibleWitnessDag
import FabricZoneTests.Ffi
import FabricZoneTests.Zone

/-!
# Tests for the session CA (src/ca)

Unit checks call the C API through `FabricZoneTests.Ffi`, each rule paired with a control that
plants the defect and must be caught. The name rule is also a plausible-witness-dag property over
deterministic candidate names: the C++ must agree with the Lean statement of the rule
(`.provablyNone` inside `searchWidth`), and a control statement that also takes uppercase letters
must be told apart (`.found`). `.budgetHit` is a failure, never a pass.
-/

open PlausibleWitnessDag FabricZoneTests

namespace FabricZoneTests

def suffix : String := ".zone.fabric.internal"

def labelOk (upper : Bool) (s : String) : Bool :=
  1 ≤ s.length && s.length ≤ 63 && s.front != '-' && s.back != '-' &&
    s.all fun ch => ch.isLower || ch.isDigit || ch == '-' || (upper && ch.isUpper)

def allowedSpec (upper : Bool) (n : String) : Bool :=
  n.endsWith suffix && labelOk upper (n.dropRight suffix.length)

def alphabet : Array Char := #['a', 'z', '0', '9', '-', 'A', '_', '.', 'x']
def suffixes : Array String := #[suffix, suffix ++ ".", ".Zone.fabric.internal", "zone.fabric.internal",
  suffix ++ "x", ".example.com", ".fabric.internal", ""]

def mix (c k : Nat) : Nat := (c * 2654435761 + k * 40503 + 12345) % 1000003

def nameAt (c : Nat) : String :=
  let len := if c % 29 == 0 then 62 + c % 4 else 1 + mix c 1 % 5
  let label := String.mk <| (List.range len).map fun i => alphabet[mix c (10 + i) % alphabet.size]!
  label ++ suffixes[mix c 2 % suffixes.size]!

def nameBreaks (broken : Bool) (c : Nat) : Bool :=
  let n := nameAt c
  (Ffi.nameAllowed n == 1) != allowedSpec broken n

def searchWidth : Nat := 20000

def firstViolation (breaks : Nat → Bool) (steps : Nat) : Option Nat :=
  (List.range steps).find? breaks

def query (name : String) (breaks : Nat → Bool) : IO TraceEntry := do
  let readback : Nat → Readback (Option Nat) := fun steps =>
    match firstViolation breaks steps with
    | some w => { value := some w, found := true, witnessIdx := w, budgetHit := false }
    | none => { value := none, found := false, budgetHit := (firstViolation breaks searchWidth).isSome }
  let (_, _, trace) ← resolve name (fun _ c => breaks c) readback
  pure trace

def expiredBit : UInt32 := 2
def chainBit : UInt32 := 1
def nameBit : UInt32 := 8
def notYetBit : UInt32 := 4

def has (flags bit : UInt32) : Bool := flags &&& bit != 0
def isErr (s : String) (code : Int) : Bool := s == s!"ERR {code}"

-- Flips one base64 digit in the PEM body's last full line: the signature's tail, same length.
def tamperSignature (pem : String) : String :=
  let lines := pem.splitOn "\n"
  let endIdx := (lines.findIdx? (·.startsWith "-----END")).getD 0
  if endIdx < 2 then pem else
    let line := lines[endIdx - 1]!
    let pos := line.length - 4
    let ch := line.get ⟨pos⟩
    let flipped := line.set ⟨pos⟩ (if ch == 'A' then 'B' else 'A')
    "\n".intercalate (lines.set (endIdx - 1) flipped)

def caChecks : IO (List (String × Bool)) := do
  let source ← Ffi.probe
  let init ← Ffi.cryptoInit
  let wall ← IO.Process.run { cmd := "date", args := #["+%s"] }
  let now := wall.trim.toNat!.toUInt64
  let ca ← Ffi.caNew (now - 3600) 86400
  let other ← Ffi.caNew (now - 3600) 86400
  let root ← Ffi.caRoot ca
  let otherRoot ← Ffi.caRoot other
  let key ← Ffi.keyNew
  let name := "player-0.zone.fabric.internal"
  let csr ← Ffi.keyCsr key name
  let keyPem ← Ffi.keyPem key
  let cert ← Ffi.caIssue ca csr name (now - 60) 3600
  let fromOther ← Ffi.caIssue other csr name (now - 60) 3600
  let expired ← Ffi.caIssue ca csr name (now - 120) 60
  let ok ← Ffi.verify root cert name now
  let otherCa ← Ffi.verify root fromOther name now
  let wrongName ← Ffi.verify root cert "player-1.zone.fabric.internal" now
  let expiredNow ← Ffi.verify root expired name now
  let expiredInside ← Ffi.verify root expired name (now - 90)
  let early ← Ffi.verify root cert name (now - 600)
  let outside ← Ffi.caIssue ca csr "player-0.example.com" now 60
  let bare ← Ffi.caIssue ca csr "zone.fabric.internal" now 60
  let longTtl ← Ffi.caIssue ca csr name now 3601
  let zeroTtl ← Ffi.caIssue ca csr name now 0
  let hour ← Ffi.caIssue ca csr name now 3600
  let broken ← Ffi.caIssue ca (tamperSignature csr) name now 60
  let exported ← Ffi.caExport ca
  pure [
    ("the entropy probe takes the OS source", source == 1),
    ("psa_crypto_init succeeds", init == 0),
    ("the root is a public certificate only", root.startsWith "-----BEGIN CERTIFICATE-----" && (root.splitOn "PRIVATE KEY").length == 1),
    ("a player key exports as PEM for its TLS stack", keyPem.startsWith "-----BEGIN"),
    ("issue a one-hour certificate", cert.startsWith "-----BEGIN CERTIFICATE-----"),
    ("it verifies against the session root", ok == 0),
    ("control: a certificate from another CA is refused", has otherCa chainBit),
    ("control: the certificate is refused for another name", has wrongName nameBit),
    ("control: a one-minute certificate from two minutes ago is refused", has expiredNow expiredBit),
    ("the same certificate verifies inside its minute", expiredInside == 0),
    ("control: a certificate is refused before its start", has early notYetBit),
    ("control: a name outside the zone suffix is not issued", isErr outside (-100)),
    ("control: the bare suffix is not issued", isErr bare (-100)),
    ("an hour exactly is issued", hour.startsWith "-----BEGIN CERTIFICATE-----"),
    ("control: an hour and a second is not issued", isErr longTtl (-101)),
    ("control: zero seconds is not issued", isErr zeroTtl (-101)),
    ("control: a CSR with a broken signature is not issued", isErr broken (-103)),
    ("control: exporting the root key is refused", exported != 0) ]

def quicChecks : IO (List (String × Bool)) := do
  let wall ← IO.Process.run { cmd := "date", args := #["+%s"] }
  let now := wall.trim.toNat!.toUInt64
  let ca ← Ffi.caNew (now - 3600) 86400
  let other ← Ffi.caNew (now - 3600) 86400
  let root ← Ffi.caRoot ca
  let otherRoot ← Ffi.caRoot other
  let zone := "zone-0.zone.fabric.internal"
  let player := "player-0.zone.fabric.internal"
  let serverKey ← Ffi.keyNew
  let clientKey ← Ffi.keyNew
  let serverCert ← Ffi.caIssue ca (← Ffi.keyCsr serverKey zone) zone (now - 60) 3600
  let clientCsr ← Ffi.keyCsr clientKey player
  let clientCert ← Ffi.caIssue ca clientCsr player (now - 60) 3600
  let foreignCert ← Ffi.caIssue other clientCsr player (now - 60) 3600
  let serverPem ← Ffi.keyPem serverKey
  let clientPem ← Ffi.keyPem clientKey
  let ok ← Ffi.quicHandshake serverCert serverPem root clientCert clientPem root zone 0
  let foreign ← Ffi.quicHandshake serverCert serverPem root foreignCert clientPem root zone 0
  let misled ← Ffi.quicHandshake serverCert serverPem root clientCert clientPem otherRoot zone 0
  let wrongName ← Ffi.quicHandshake serverCert serverPem root clientCert clientPem root "zone-1.zone.fabric.internal" 0
  let expiredCert ← Ffi.caIssue ca clientCsr player (now - 120) 60
  let expired ← Ffi.quicHandshake serverCert serverPem root expiredCert clientPem root zone 0
  let tampered ← Ffi.quicHandshake serverCert serverPem root clientCert clientPem root zone 1
  pure [
    (s!"QUIC with mutual TLS, a WebTransport session, a datagram each way, no plaintext relayed ({ok}, want 1122)", ok == 1122),
    (s!"control: a client certificate from another CA is refused ({foreign})", foreign % 100 != 22),
    (s!"control: a client that trusts another root refuses the zone ({misled})", misled % 100 != 22),
    (s!"control: the wrong server name is refused ({wrongName})", wrongName % 100 != 22),
    (s!"control: an expired client certificate ends the handshake ({expired})", expired % 100 != 22),
    (s!"control: a datagram with one flipped byte does not arrive ({tampered}, session up without the 1000)",
      tampered % 1000 == 122) ]

def hexByte (c : Char) : UInt8 :=
  if c.isDigit then (c.toNat - '0'.toNat).toUInt8 else (c.toNat - 'a'.toNat + 10).toUInt8

def hexBytes (s : String) : ByteArray := Id.run do
  let cs := s.toList.toArray
  let mut out := ByteArray.empty
  for i in [0:cs.size / 2] do
    out := out.push (hexByte cs[2 * i]! * 16 + hexByte cs[2 * i + 1]!)
  return out

-- RFC 9180 Appendix A.3, DHKEM(P-256, HKDF-SHA256): ikmE and ikmR with the public keys DeriveKeyPair gives.
def ikmE : String := "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e"
def pkEm : String := "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
def ikmR : String := "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550"
def pkRm : String := "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"

def offlineChecks : IO (List (String × Bool)) := do
  let wall ← IO.Process.run { cmd := "date", args := #["+%s"] }
  let now := wall.trim.toNat!.toUInt64
  let seed := hexBytes ikmE
  let flipped := seed.set! 0 (seed.get! 0 ^^^ 1)
  let a ← Ffi.caNewSeeded seed (now - 3600) 86400
  let b ← Ffi.caNewSeeded seed (now - 60) 86400
  let r ← Ffi.caNewSeeded (hexBytes ikmR) (now - 3600) 86400
  let f ← Ffi.caNewSeeded flipped (now - 3600) 86400
  let short ← Ffi.caNewSeeded (seed.extract 0 31) (now - 3600) 86400
  let session ← Ffi.caNew (now - 3600) 86400
  let pubA ← Ffi.caRootPublicHex a
  let pubB ← Ffi.caRootPublicHex b
  let pubR ← Ffi.caRootPublicHex r
  let pubF ← Ffi.caRootPublicHex f
  let rootB ← Ffi.caRoot b
  let rootR ← Ffi.caRoot r
  let key ← Ffi.keyNew
  let peer := "cluster-0.fdb.fabric.internal"
  let csr ← Ffi.keyCsr key peer
  let cert ← Ffi.caIssue a csr peer (now - 60) 3600
  let laterRun ← Ffi.verify rootB cert peer now
  let otherSeed ← Ffi.verify rootR cert peer now
  let zoneName ← Ffi.caIssue a csr "zone-0.zone.fabric.internal" now 60
  let fdbFromSession ← Ffi.caIssue session csr peer now 60
  let exported ← Ffi.caExport a
  pure [
    ("RFC 9180 DeriveKeyPair: ikmE gives pkEm", pubA == pkEm),
    ("RFC 9180 DeriveKeyPair: ikmR gives pkRm", pubR == pkRm),
    ("the same seed gives the same root key in another run", pubB == pkEm),
    ("control: one flipped seed bit gives another key", pubF.length == pkEm.length && pubF != pkEm),
    ("a certificate from one run verifies against the root another run made from the same seed", laterRun == 0),
    ("control: the root from a different seed refuses it", has otherSeed chainBit),
    ("control: a 31-byte seed makes no CA", short == 0),
    ("the offline root issues an FDB peer name", cert.startsWith "-----BEGIN CERTIFICATE-----"),
    ("control: the offline root does not issue a zone name", isErr zoneName (-100)),
    ("control: the session root does not issue an FDB peer name", isErr fdbFromSession (-100)),
    ("control: exporting the offline root key is refused", exported != 0) ]

def entropyChecks : IO (List (String × Bool)) := do

  Ffi.forceHost 1
  let starved ← Ffi.probe
  let fedOk ← Ffi.feed (ByteArray.mk ((List.range 32).map fun i => (mix 7 i % 251 + 1).toUInt8).toArray)
  let fed ← Ffi.probe
  let zeros ← Ffi.feed (ByteArray.mk (List.replicate 32 (0 : UInt8)).toArray)
  let allZero ← Ffi.probe
  Ffi.forceHost 0
  pure [
    ("control: with the OS source off and the pool empty, the probe fails", starved == (0 - 106 : Int32).toUInt32),
    ("fed host bytes are taken when the OS source is off", fedOk == 0 && fed == 2),
    ("control: all-zero host bytes are refused", zeros == 0 && allZero == (0 - 106 : Int32).toUInt32) ]

end FabricZoneTests

open FabricZoneTests in
def main : IO UInt32 := do
  let unit := (← caChecks) ++ (← quicChecks) ++ (← offlineChecks) ++ (← entropyChecks)
  let mut bad := 0
  for (name, ok) in unit do
    IO.println s!"{if ok then "ok  " else "FAIL"} {name}"
    unless ok do bad := bad + 1
  let label := "the C++ name rule is the Lean rule (control: the rule also takes uppercase)"
  let real ← query label (nameBreaks false)
  let control ← query s!"control: {label}" (nameBreaks true)
  let realOk := real.outcome == .provablyNone
  let controlOk := match control.outcome with | .found _ => true | _ => false
  IO.println s!"{if realOk && controlOk then "ok  " else "FAIL"} {label}: real {repr real.outcome}, control {repr control.outcome}"
  unless realOk && controlOk do bad := bad + 1
  bad := bad + (← FabricZoneTests.Zone.run)
  IO.println s!"RESULT: {if bad == 0 then "PASS" else s!"FAIL ({bad})"}"
  return (if bad == 0 then 0 else 1)
