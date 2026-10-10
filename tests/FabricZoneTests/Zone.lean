-- SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
-- SPDX-License-Identifier: MIT
import PlausibleWitnessDag

/-!
# The zone, casync, pose and journal C++, through tests/ffi/zone_shim.cpp

Each trial is deterministic in its seed; the `UInt8` flag plants the defect a control catches.
Unit checks, then properties, each property with its control; `run` returns the failure count.
-/

open PlausibleWitnessDag

namespace FabricZoneTests.Zone

@[extern "fz_lean_sha512_256"] opaque sha512_256 : @& ByteArray → ByteArray
@[extern "fz_lean_handover_trial"] opaque handoverTrial : UInt32 → UInt8 → UInt32
@[extern "fz_lean_fetch_trial"] opaque fetchTrial : UInt32 → UInt8 → UInt8
@[extern "fz_lean_caibx_trial"] opaque caibxTrial : UInt32 → UInt8 → UInt8
@[extern "fz_lean_pose_trial"] opaque poseTrial : UInt32 → UInt8 → Float
@[extern "fz_lean_bone_index"] opaque boneIndex : @& String → UInt32
@[extern "fz_lean_journal_trial"] opaque journalTrial : UInt32 → UInt8 → UInt8
@[extern "fz_lean_handover_payload_trial"] opaque handoverPayloadTrial : UInt32 → UInt8 → UInt8
@[extern "fz_lean_zone_reopen_trial"] opaque zoneReopenTrial : UInt32 → UInt8 → UInt8
@[extern "fz_lean_pose_relay_trial"] opaque poseRelayTrial : UInt32 → UInt8 → UInt8

def hex (b : ByteArray) : String :=
  String.join (b.toList.map fun x =>
    let h := "0123456789abcdef".toList
    String.ofList [h[(x / 16).toNat]!, h[(x % 16).toNat]!])

def ascii (s : String) : ByteArray := s.toUTF8

/-- The 53 humanoid roles both avatars' .fbx.meta files declare. -/
def avatarRoles : List String :=
  ["Chest", "Head", "Hips", "LeftEye", "LeftFoot", "LeftHand", "Left Index Distal",
   "Left Index Intermediate", "Left Index Proximal", "Left Little Distal", "Left Little Intermediate",
   "Left Little Proximal", "LeftLowerArm", "LeftLowerLeg", "Left Middle Distal", "Left Middle Intermediate",
   "Left Middle Proximal", "Left Ring Distal", "Left Ring Intermediate", "Left Ring Proximal", "LeftShoulder",
   "Left Thumb Distal", "Left Thumb Intermediate", "Left Thumb Proximal", "LeftToes", "LeftUpperArm",
   "LeftUpperLeg", "Neck", "RightEye", "RightFoot", "RightHand", "Right Index Distal",
   "Right Index Intermediate", "Right Index Proximal", "Right Little Distal", "Right Little Intermediate",
   "Right Little Proximal", "RightLowerArm", "RightLowerLeg", "Right Middle Distal",
   "Right Middle Intermediate", "Right Middle Proximal", "Right Ring Distal", "Right Ring Intermediate",
   "Right Ring Proximal", "RightShoulder", "Right Thumb Distal", "Right Thumb Intermediate",
   "Right Thumb Proximal", "RightToes", "RightUpperArm", "RightUpperLeg", "Spine"]

-- ── Unit checks ──────────────────────────────────────────────────────────────

def unitChecks : List (String × Bool) :=
  let indices := avatarRoles.map boneIndex
  [ ("SHA-512/256 of the empty string (FIPS 180-4 vector)",
      hex (sha512_256 ByteArray.empty) == "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a"),
    ("SHA-512/256 of \"abc\" (FIPS 180-4 vector)",
      hex (sha512_256 (ascii "abc")) == "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"),
    ("both avatars' 53 roles have distinct bone indices",
      avatarRoles.length == 53 && indices.all (· < 55) && indices.eraseDups.length == 53),
    ("an unknown role name has no bone index", boneIndex "Tail" == 0xFFFFFFFF),
    ("a corrupted chunk makes the fetch fail rather than return wrong bytes",
      (List.range 20).any fun c => fetchTrial c.toUInt32 1 == 2),
    ("a hand-over with a lossy datagram channel still ends owned by the players' zone",
      (handoverTrial 7 0 &&& 8) == 8) ]

-- ── Properties, each with a control that plants the defect ───────────────────

def searchWidth : Nat := 200

def ownerBreaks (broken : Bool) (c : Nat) : Bool :=
  let r := handoverTrial c.toUInt32 (if broken then 1 else 0)
  (r &&& 3) > 1 || (r &&& 4) != 0 || (r &&& 8) == 0

def fetchBreaks (broken : Bool) (c : Nat) : Bool :=
  fetchTrial c.toUInt32 (if broken then 1 else 0) != 1

def caibxBreaks (broken : Bool) (c : Nat) : Bool :=
  caibxTrial c.toUInt32 (if broken then 1 else 0) != 1

def poseBreaks (broken : Bool) (c : Nat) : Bool :=
  let e := poseTrial c.toUInt32 (if broken then 1 else 0)
  e < 0.0 || e > 1.6e-5

def journalBreaks (broken : Bool) (c : Nat) : Bool :=
  journalTrial c.toUInt32 (if broken then 1 else 0) != 1

def payloadBreaks (broken : Bool) (c : Nat) : Bool :=
  handoverPayloadTrial c.toUInt32 (if broken then 1 else 0) != 1

def reopenBreaks (broken : Bool) (c : Nat) : Bool :=
  zoneReopenTrial c.toUInt32 (if broken then 1 else 0) != 1

def relayBreaks (broken : Bool) (c : Nat) : Bool :=
  poseRelayTrial c.toUInt32 (if broken then 1 else 0) != 1

def firstViolation (breaks : Nat → Bool) (steps : Nat) : Option Nat :=
  (List.range steps).find? breaks

def query (name : String) (breaks : Nat → Bool) : IO TraceEntry := do
  let readback : Nat → Readback (Option Nat) := fun steps =>
    match firstViolation breaks steps with
    | some w => { value := some w, found := true, witnessIdx := w, budgetHit := false }
    | none => { value := none, found := false, budgetHit := (firstViolation breaks searchWidth).isSome }
  let (_, _, trace) ← resolve name (fun _ c => breaks c) readback
  pure trace

def properties : List (String × (Bool → Nat → Bool)) := [
  ("one zone owns the garment at every tick through a hand-over, none loses it (control: hand over without STAGING)",
    ownerBreaks),
  ("a fetched asset equals what was stored (control: one stored chunk corrupted)", fetchBreaks),
  (".caibx write and parse round-trip the chunk table (control: items hold start offsets, as upload_asset wrote them)",
    caibxBreaks),
  ("a pose survives the wire within 1.6e-5 per component (control: the packet loses its last byte)", poseBreaks),
  ("a journal replayed from its last flush restores every slot (control: replay from the flush before the last mutation)",
    journalBreaks),
  ("a zone reopened from its journal holds the same entities and payloads (control: open without replay)",
    reopenBreaks),
  ("a hand-over carries the garment's payload, and the receiving zone's journal keeps it (control: the intent drops the payload)",
    payloadBreaks),
  ("each player sees the other's pose through the zone (control: a player claims the other's id)", relayBreaks) ]


def run : IO Nat := do
  let mut bad := 0
  for (name, ok) in unitChecks do
    IO.println s!"{if ok then "ok  " else "FAIL"} {name}"
    unless ok do bad := bad + 1
  for (name, breaks) in properties do
    let real ← query name (breaks false)
    let control ← query s!"control: {name}" (breaks true)
    let realOk := real.outcome == .provablyNone
    let controlOk := match control.outcome with | .found _ => true | _ => false
    IO.println s!"{if realOk && controlOk then "ok  " else "FAIL"} {name}: real {repr real.outcome}, control {repr control.outcome}"
    unless realOk && controlOk do bad := bad + 1
  return bad

end FabricZoneTests.Zone
