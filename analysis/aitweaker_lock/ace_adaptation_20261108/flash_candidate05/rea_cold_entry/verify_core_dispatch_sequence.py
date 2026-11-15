"""Execute ACE's actual DXE dependency evaluator/dispatcher before native Setup.

The PE loader, protocol database, TPL/event providers and early hardware helpers
are fixtures. The original dispatcher, dependency evaluator, scheduler, native
AMITSE initializer/BDS path and compiled candidate driver execute in Unicorn.
This is bounded control-flow evidence, not a physical cold-boot result.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import lzma
import struct
import sys
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
BASE = ROOT / "analysis/aitweaker_lock/ace_adaptation_20261108"
CORE_FILE = BASE / "integration03_rea_review/modules/OriginalDxeCore.efi"
CAP_FILE = ROOT / "analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP"
CORE_SHA = "6259bedcef838d21e9f48a86e28ecea0e399c216681c7543cf727fa38023c6a7"
CAP_SHA = "03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29"
DRIVER_SHA = "71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98"
CORE = 0x40000000
WORK = 0x41000000
GUID = lambda value: uuid.UUID(value).bytes_le
VAR = GUID("1e5668e2-8481-11d4-bcf1-0080c73c8881")
WRITE = GUID("6441f818-6362-4e44-b570-7dba31dd2453")
AMITSE_GUID = GUID("b1da0adf-4f77-4070-a88e-bffe1c60529a")
SETUP_GUID = GUID("899407d7-99fe-43d8-9a21-79ec328cac21")
APRIORI_GUID = GUID("fc510ee7-ffdc-11d4-bd41-0080c73c8881")
DRIVER_GUID = GUID("97f9cf3d-1209-4c68-a827-e547d0531904")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sections(data):
    result = []
    pos = 0
    while pos + 4 <= len(data):
        size = int.from_bytes(data[pos:pos+3], "little")
        assert size >= 4 and pos + size <= len(data)
        kind = data[pos+3]
        body = data[pos+4:pos+size]
        row = {"type": hex(kind), "bytes": size, "sha256": sha(data[pos:pos+size])}
        if kind == 2:
            assert body[:16] == GUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf")
            assert body[16:20] == b"\x18\0\x01\0"
            unpacked = lzma.decompress(body[20:], format=lzma.FORMAT_ALONE)
            row["decoded_sha256"] = sha(unpacked)
            row["children"] = sections(unpacked)
        if kind in (0x13, 0x19):
            row["payload_hex"] = body.hex()
        result.append(row)
        pos = (pos + size + 3) & ~3
    return result


def inventory():
    data = CAP_FILE.read_bytes()
    assert sha(data) == CAP_SHA
    section = 0x3181090
    size = int.from_bytes(data[section:section+3], "little")
    raw = lzma.decompress(data[section+24:section+size], format=lzma.FORMAT_ALONE)
    fv = 16
    header = struct.unpack_from("<H", raw, fv+48)[0]
    pos = (fv + header + 7) & ~7
    selected = {}
    while pos + 24 <= len(raw):
        if raw[pos:pos+24] == b"\xff" * 24:
            break
        size = int.from_bytes(raw[pos+20:pos+23], "little")
        assert size >= 24
        guid = raw[pos:pos+16]
        if guid in (AMITSE_GUID, SETUP_GUID, APRIORI_GUID):
            selected[str(uuid.UUID(bytes_le=guid))] = {
                "offset_in_decoded_container": hex(pos), "ffs_size": size,
                "ffs_sha256": sha(raw[pos:pos+size]), "ffs_type": hex(raw[pos+18]),
                "sections": sections(raw[pos+24:pos+size]),
            }
        pos = (pos + size + 7) & ~7
    amitse = selected[str(uuid.UUID(bytes_le=AMITSE_GUID))]
    setup = selected[str(uuid.UUID(bytes_le=SETUP_GUID))]
    apriori = selected[str(uuid.UUID(bytes_le=APRIORI_GUID))]
    assert [s["type"] for s in amitse["sections"]] == ["0x2"]
    assert [s["type"] for s in amitse["sections"][0]["children"]] == ["0x10", "0x15"]
    assert len(setup["sections"]) == 3
    setup_depex = bytes.fromhex(setup["sections"][0]["payload_hex"])
    assert setup_depex[0] == 2 and VAR in setup_depex and WRITE in setup_depex
    apriori_bytes = bytes.fromhex(apriori["sections"][0]["payload_hex"])
    apriori_list = [str(uuid.UUID(bytes_le=apriori_bytes[i:i+16])) for i in range(0, len(apriori_bytes), 16)]
    assert str(uuid.UUID(bytes_le=AMITSE_GUID)) not in apriori_list
    assert str(uuid.UUID(bytes_le=DRIVER_GUID)) not in apriori_list
    return {"capsule_sha256": CAP_SHA, "decoded_container_sha256": sha(raw),
            "selected_files": selected, "original_apriori_guids": apriori_list,
            "amitse_has_depex": False, "amitse_in_original_apriori": False,
            "setup_requires_variable_arch_and_write_arch": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, default=BASE / "flash_candidate05/lock_1904_candidate05/driver/build")
    args = parser.parse_args()
    build = args.build.resolve()
    assert sha(CORE_FILE.read_bytes()) == CORE_SHA
    assert sha((build / "AiTweakerLock1904.efi").read_bytes()) == DRIVER_SHA
    native_inventory = inventory()
    original = HERE / "verify_native_cold_sequence.py"
    source = original.read_text(encoding="utf8")
    marker = "    rows = []\n    scenarios = "
    assert source.count(marker) == 1
    derived = source.replace(marker, '    globals()["ColdVM"] = ColdVM\n    return\n\n' + marker)
    derived_path = HERE / "core_sequence_base.fixture.py"
    derived_path.write_text(derived, encoding="utf8")
    ns = {"__name__": "core_sequence_base", "__file__": str(derived_path)}
    exec(compile(derived, str(derived_path), "exec"), ns)
    saved_argv = sys.argv
    sys.argv = [str(derived_path), "--build", str(build)]
    try:
        ns["main"]()
    finally:
        sys.argv = saved_argv
    globals().update({k: ns[k] for k in ("ColdVM", "U", "R", "TSE", "BDS", "HEAP", "STOP", "symbols", "q", "d", "ERR", "pefile")})
    done = STOP + 0x7c00
    bds_bridge = STOP + 0x7c10
    driver_depex = b"\x02" + VAR + b"\x02" + WRITE + b"\x03\x08"

    class CoreVM(ColdVM):
        def __init__(self, order, delayed_write=False):
            self.core_frames = []
            self.core_started = []
            self.core_loads = []
            self.variable_write_available = not delayed_write
            self.delayed_write = delayed_write
            self.images = {}
            self.at_core_bds_boundary = False
            super().__init__("formbrowser", True)
            pe = pefile.PE(str(CORE_FILE)); pe.relocate_image(CORE)
            raw = pe.get_memory_mapped_image()
            self.map(CORE, (len(raw)+4095) & ~4095); self.u.mem_write(CORE, raw)
            self.map(WORK, 0x100000)
            self.u.mem_write(CORE+0x17b20, b"\0")
            # Two representative architectural protocol records and a sentinel.
            # Other architectural protocols are stipulated ready by the fixture.
            for index, ready in enumerate((True, not delayed_write)):
                self.u.mem_write(CORE+0x162e0+index*0x28, q(WORK+0x100+index*16))
                self.u.mem_write(CORE+0x16300+index*0x28, bytes([ready]))
            self.u.mem_write(CORE+0x16330, bytes(0x28))
            self.u.mem_write(CORE+0x17b98, q(WORK+0x800))
            self.u.mem_write(CORE+0x17ba0, q(WORK+0x900))
            self.u.mem_write(CORE+0x17ba8, q(WORK+0x800))
            queue = CORE+0x16b78
            self.u.mem_write(queue, q(queue)+q(queue))
            discovered = CORE+0x16b98
            bases = [WORK+0x1000+i*0x200 for i in range(len(order))]
            self.u.mem_write(discovered, q(bases[0]+8)+q(bases[-1]+8))
            for index, (base, name) in enumerate(zip(bases, order)):
                link = base+8
                prior = bases[index-1]+8 if index else discovered
                following = bases[index+1]+8 if index+1 < len(bases) else discovered
                self.u.mem_write(link, q(following)+q(prior))
                self.u.mem_write(base+0x30, DRIVER_GUID if name == "driver" else AMITSE_GUID if name == "amitse" else GUID("01010101-0101-0101-0101-010101010101"))
                self.u.mem_write(base+0x40, q(base))
                self.u.mem_write(base+0x74, b"\1")
                if name != "amitse":
                    depex = driver_depex if name == "driver" else b"\x06\x08"
                    self.u.mem_write(base+0x100, depex)
                    self.u.mem_write(base+0x50, q(base+0x100)+q(len(depex)))
                self.images[base] = name
            self.u.mem_write(CORE+0x17a70, q(WORK+0x600))
            self.u.mem_write(WORK+0x600, q(bds_bridge))
            addresses = [0x9354, 0x9560, 0x9760, 0xe6ec, 0xcc98, 0x11268, 0x111b8, 0x8620, 0x8720, 0xabbc]
            for address in [CORE+a for a in addresses] + [done, bds_bridge]:
                self.u.hook_add(U.UC_HOOK_CODE, self.hook, begin=address, end=address)

        def hook(self, u, address, size, data):
            if address == CORE+0x9354:
                u.mem_write(self.argn(5), q(WORK+0x500)); self.ret(0); return
            if address in [CORE+a for a in (0x9560, 0x9760, 0xe6ec, 0xcc98, 0x11268, 0x111b8)]:
                self.ret(0); return
            if address == CORE+0xabbc:
                guid = bytes(u.mem_read(self.arg(0), 16))
                present = guid == VAR or (guid == WRITE and self.variable_write_available)
                if present:
                    u.mem_write(self.arg(2), q(WORK+0x400))
                self.ret(0 if present else ERR(14)); return
            if address == CORE+0x8620:
                token = self.arg(2)
                assert token in self.images
                self.core_loads.append(self.images[token])
                u.mem_write(self.argn(5), q(token))
                self.record("Core_LoadImage_provider_success", image=self.images[token])
                self.ret(0); return
            if address == CORE+0x8720:
                name = self.images[self.arg(0)]
                self.core_started.append(name)
                self.record("Core_StartImage_calls_actual_entry", image=name)
                if name == "variable-provider":
                    self.variable_write_available = True
                    u.mem_write(CORE+0x16328, b"\1")
                    self.record("fixture_variable_write_arch_published")
                    self.ret(0); return
                self.core_frames.append({"outer": u.context_save(), "name": name})
                sp = 0x70000000+0x300000-0x10000*len(self.core_frames)+0xfe08
                u.mem_write(sp, q(done)+bytes(0x100))
                u.reg_write(R.UC_X86_REG_RSP, sp)
                u.reg_write(R.UC_X86_REG_RCX, 0xcafe if name == "driver" else 0xabc1)
                u.reg_write(R.UC_X86_REG_RDX, self.st)
                u.reg_write(R.UC_X86_REG_RIP, symbols["efi_main"] if name == "driver" else TSE+0x1034)
                return
            if address == done:
                status = u.reg_read(R.UC_X86_REG_RAX)
                frame = self.core_frames.pop()
                self.record("actual_entry_returned_to_Core", image=frame["name"], result=hex(status))
                assert status == 0
                u.context_restore(frame["outer"]); self.ret(status); return
            if address == bds_bridge:
                self.record("Core_reached_BDS_after_dispatcher", images_started=list(self.core_started))
                self.at_core_bds_boundary = True
                u.emu_stop(); return
            super().hook(u, address, size, data)

        def core_until_bds(self):
            sp = 0x70000000+0x3f0000
            self.u.mem_write(sp, bytes(0x200))
            self.u.reg_write(R.UC_X86_REG_RSP, sp)
            # Execute original Core block calling the dispatcher, validating
            # architecture readiness and calling BDS through its real slot.
            self.u.reg_write(R.UC_X86_REG_RSI, CORE+0x162e0)
            self.u.reg_write(R.UC_X86_REG_R15, 0)
            self.u.reg_write(R.UC_X86_REG_R13, 0)
            self.u.emu_start(CORE+0x24d4, 0, count=200000000)
            assert self.at_core_bds_boundary

    rows = []
    for name, order, delayed in [
        ("driver listed before AMITSE", ["driver", "amitse"], False),
        ("driver listed after AMITSE", ["amitse", "driver"], False),
        ("initially unsatisfied dependencies rechecked after provider", ["amitse", "driver", "variable-provider"], True),
    ]:
        vm = CoreVM(order, delayed)
        vm.core_until_bds()
        before_bds = {"ready": vm.getd(symbols["platform_ready"]), "manager": vm.getd(symbols["manager_installed"]),
                      "depth": vm.getd(symbols["loop_depth"]), "stage": vm.getq(TSE+0x82628)}
        assert before_bds == {"ready": 1, "manager": 1, "depth": 0, "stage": 0}
        vm.bds_until_cache()
        assert vm.cache_reached and vm.getd(symbols["loop_depth"]) == 1
        assert vm.u.mem_read(symbols["password_core"]+200, 1)[0] == 1
        rows.append({"case": name, "discovered_order": order, "started_order": vm.core_started,
                     "before_BDS": before_bds, "first_native_cache_owned": True, "hii_package_updates": vm.update_calls,
                     "trace": vm.trace})
        print("PASS", name, flush=True)
    report = {"status": "PASS_CONDITIONAL_ORDINARY_DXE_ORDERING", "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "driver_sha256": DRIVER_SHA, "original_core_sha256": CORE_SHA,
              "cases": len(rows), "rows": rows, "original_firmware_inventory": native_inventory,
              "driver_depex_hex": driver_depex.hex(), "source_sha256": sha(Path(__file__).read_bytes()),
              "base_fixture_sha256": sha(original.read_bytes()), "derived_fixture_sha256": sha(derived_path.read_bytes()),
              "production_changes": False, "device_access": False,
              "conditions": ["Both images have been discovered in the same decoded FV.", "Image authentication, allocation and loading succeed.",
                             "Original Setup image and matching SMBIOS are already present as provided by the base fixture.",
                             "Variable providers, HII services and required memory permissions are available and attachment succeeds.",
                             "Normal Core dispatcher-to-BDS path is followed; no provider invokes Setup during DXE initialization."],
              "limits": ["No hardware Del/F2 key acquisition, full page rendering, persistence, image authentication or complete PE loader execution is claimed.",
                         "Original dispatcher, DEPEX evaluator and scheduler run; LoadImage/StartImage providers supply mapped images and call actual selected entry code.",
                         "Core Main's 0x24d4 block executes with documented live registers; earlier platform/Core initialization is not replayed.",
                         "AMITSE entry is exercised from its main initializer 0x1034 with explicitly stubbed hardware helpers, as documented by the base fixture.",
                         "Three additional ordering cases complement, rather than replace or sum as independent hardware acceptance with, the six prior bounded native cases."]}
    out = HERE / "core_dispatch_sequence.json"
    out.write_text(json.dumps(report, indent=2)+"\n", encoding="utf8")
    print(json.dumps({"status": report["status"], "cases": len(rows), "output": str(out)}))


if __name__ == "__main__":
    main()
