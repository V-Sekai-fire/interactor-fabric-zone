#!/usr/bin/env python3
"""Checks that each guest ELF is the variant the pinned double engine loads.

  python3 tools/check_elf.py project/*.elf
  python3 tools/check_elf.py --self-test project/ca.elf

A guest passes when it is a static riscv64 ELF, its .sandbox_variant section reads SBXV 28000000 (a
40-byte, double-precision Variant), its .riscv.attributes arch has no V extension, it keeps .symtab
(the Sandbox finds the guest's functions there, so -s is refused) and it has no .debug_ section
(--strip-debug). --self-test plants each defect in a copy of the ELF and requires every copy to fail.
"""
import struct
import sys

EM_RISCV = 243
VARIANT = b"SBXV" + struct.pack("<I", 40)


def sections(elf):
    if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF")
    machine = struct.unpack_from("<H", elf, 0x12)[0]
    shoff = struct.unpack_from("<Q", elf, 0x28)[0]
    entsize, count, strndx = struct.unpack_from("<HHH", elf, 0x3A)
    heads = [struct.unpack_from("<IIQQQQ", elf, shoff + i * entsize) for i in range(count)]
    stroff = heads[strndx][4]
    out = {}
    for name, _type, _flags, _addr, off, size in heads:
        end = elf.index(b"\0", stroff + name)
        out[elf[stroff + name:end].decode()] = (off, size)
    return machine, out


def arch(attrs):
    # Tag_RISCV_arch (5) is followed by a NUL-terminated string such as rv64i2p1_m2p0_..._c2p0_zicsr2p0.
    at = attrs.find(b"rv64")
    if at < 0:
        return ""
    return attrs[at:attrs.index(b"\0", at)].decode()


def has_vector(arch_string):
    parts = arch_string.split("_")
    base = parts[0][len("rv64"):]
    # The single-letter extensions sit in the first part, each with its version: i2p1m2p0...
    letters = "".join(c for c in base if c.isalpha() and c != "p")
    return "v" in letters or any(p.startswith(("v", "zve", "zvl")) for p in parts[1:])


def check(elf):
    """Returns a list of problems; empty when the ELF passes."""
    try:
        machine, secs = sections(elf)
    except (ValueError, IndexError, struct.error) as e:
        return ["unreadable ELF: %s" % e]
    bad = []
    if machine != EM_RISCV:
        bad.append("e_machine %d, not RISC-V" % machine)
    if ".sandbox_variant" not in secs:
        bad.append("no .sandbox_variant section")
    else:
        off, size = secs[".sandbox_variant"]
        got = elf[off:off + size]
        if got != VARIANT:
            bad.append(".sandbox_variant reads %s, not SBXV 28000000 (double)" % got.hex())
    if ".riscv.attributes" not in secs:
        bad.append("no .riscv.attributes section")
    else:
        off, size = secs[".riscv.attributes"]
        a = arch(elf[off:off + size])
        if not a:
            bad.append("no arch string in .riscv.attributes")
        elif has_vector(a):
            bad.append("arch %s has the V extension" % a)
    if ".symtab" not in secs:
        bad.append("no .symtab (stripped with -s, not --strip-debug)")
    debug = sorted(s for s in secs if s.startswith(".debug_"))
    if debug:
        bad.append("debug sections left: %s" % ", ".join(debug))
    return bad


def plant(elf, what):
    b = bytearray(elf)
    _, secs = sections(elf)
    if what == "single":
        off, _ = secs[".sandbox_variant"]
        b[off + 4:off + 8] = struct.pack("<I", 24)
    elif what == "vector":
        off, size = secs[".riscv.attributes"]
        at = bytes(b[off:off + size]).find(b"_zicsr")
        if at < 0:
            raise SystemExit("FAIL self-test: no _zicsr in the arch string to replace")
        b[off + at:off + at + 6] = b"_zve32"
    elif what == "stripped":
        shoff = struct.unpack_from("<Q", elf, 0x28)[0]
        entsize, count, strndx = struct.unpack_from("<HHH", elf, 0x3A)
        stroff = struct.unpack_from("<IIQQQQ", elf, shoff + strndx * entsize)[4]
        name = bytes(b).index(b".symtab\0", stroff)
        b[name:name + 7] = b".nosymt"
    elif what == "debug":
        name = bytes(b).index(b".comment\0")
        b[name:name + 8] = b".debug_x"
    elif what == "truncated":
        del b[len(b) // 2:]
    return bytes(b)


def main(argv):
    self_test = "--self-test" in argv
    paths = [a for a in argv if a != "--self-test"]
    if not paths:
        raise SystemExit(__doc__)
    failed = 0
    for path in paths:
        elf = open(path, "rb").read()
        bad = check(elf)
        print(("PASS " if not bad else "FAIL ") + path + ("" if not bad else ": " + "; ".join(bad)))
        failed += bool(bad)
        if self_test and not bad:
            for what in ("single", "vector", "stripped", "debug", "truncated"):
                refused = check(plant(elf, what))
                print(("PASS " if refused else "FAIL ") + "control %s: %s is refused (%s)" %
                      (what, path, "; ".join(refused) or "accepted"))
                failed += not refused
    print("RESULT: %s" % ("PASS" if failed == 0 else "FAIL (%d)" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
