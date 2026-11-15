"""Bounded offline ARM PDK replay. No network, target execution, or CAP output.

Unicorn executes the pinned PDK function's actual instructions. File/console/
allocation imports are closed stubs; crypto imports use the already installed
host OpenSSL DLL. Ephemeral test private keys remain native OpenSSL handles:
no private-key export, serialization, printing, or persistence is implemented.
Only this program's JSON report is written. The temporary re-signed capsule is
never written, uploaded, or exposed by the report.
"""
from __future__ import annotations

import ctypes as C
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / "tools/pydeps").is_dir())
sys.path.insert(0, str(ROOT / "tools/pydeps"))
import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


elf_module = load_module("pdk_elf_metadata", HERE / "component_backend_review/build_component_evidence.py")
capsule = load_module("pdk_capsule_reference", HERE.parent / "verify_capsule_static.py")
PDK = HERE / "bmc_backend/5308416/usr/local/lib/libpdkapp.so.13.2.4"
PIN_PDK = "35459aed01642e815001dc0e319f25ac79ae3ed72607d0895452513ebe38b567"
LIBCRYPTO = Path("D:/OpenSSL-Win64/bin/libcrypto-4-x64.dll")
PIN_CRYPTO = "1bf007ea75d38ef1f8a4edcfb2bcec65a1d3237499c5ff38fee9a568a8de058c"
REPORT = HERE / "capsule_trust_replay.json"
BASE, CAP_BASE, STACK_BASE, HALT = 0x10000, 0x10000000, 0x08000000, 0x07000000
STACK_SIZE = 0x20000
REGS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def artifact(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": sha(data)}


class Crypto:
    """Typed bindings; only public parameters n/e are requested for export."""
    def __init__(self):
        require(sha(LIBCRYPTO.read_bytes()) == PIN_CRYPTO, "host libcrypto pin differs")
        self.lib = C.CDLL(str(LIBCRYPTO))
        ptr, integer, size, pp = C.c_void_p, C.c_int, C.c_size_t, C.POINTER(C.c_void_p)
        signatures = {
            "RSA_new": (ptr, []), "RSA_free": (None, [ptr]),
            "BN_bin2bn": (ptr, [ptr, integer, ptr]), "BN_free": (None, [ptr]),
            "BN_bn2binpad": (integer, [ptr, ptr, integer]),
            "RSA_set0_key": (integer, [ptr, ptr, ptr, ptr]),
            "EVP_PKEY_new": (ptr, []), "EVP_PKEY_free": (None, [ptr]),
            "EVP_PKEY_assign": (integer, [ptr, integer, ptr]),
            "EVP_MD_CTX_new": (ptr, []), "EVP_MD_CTX_free": (None, [ptr]),
            "EVP_PKEY_CTX_new": (ptr, [ptr, ptr]), "EVP_PKEY_CTX_free": (None, [ptr]),
            "EVP_sha256": (ptr, []),
            "EVP_DigestVerifyInit": (integer, [ptr, pp, ptr, ptr, ptr]),
            "RSA_pkey_ctx_ctrl": (integer, [ptr, integer, integer, integer, ptr]),
            "EVP_DigestUpdate": (integer, [ptr, ptr, size]),
            "EVP_DigestVerifyFinal": (integer, [ptr, ptr, size]),
            "EVP_PKEY_CTX_new_id": (ptr, [integer, ptr]),
            "EVP_PKEY_keygen_init": (integer, [ptr]),
            "EVP_PKEY_CTX_set_rsa_keygen_bits": (integer, [ptr, integer]),
            "EVP_PKEY_keygen": (integer, [ptr, pp]),
            "EVP_PKEY_get_bn_param": (integer, [ptr, C.c_char_p, pp]),
            "EVP_PKEY_sign_init": (integer, [ptr]),
            "EVP_PKEY_CTX_set_rsa_padding": (integer, [ptr, integer]),
            "EVP_PKEY_CTX_set_rsa_pss_saltlen": (integer, [ptr, integer]),
            "EVP_PKEY_CTX_set_rsa_mgf1_md": (integer, [ptr, ptr]),
            "EVP_PKEY_CTX_set_signature_md": (integer, [ptr, ptr]),
            "EVP_PKEY_sign": (integer, [ptr, ptr, C.POINTER(size), ptr, size]),
            "OpenSSL_version": (C.c_char_p, [integer]),
        }
        for name, (result, args) in signatures.items():
            f = getattr(self.lib, name)
            f.restype, f.argtypes = result, args
        self.bound_names = sorted(signatures)
        self.ephemeral = []

    def keygen(self):
        context = self.lib.EVP_PKEY_CTX_new_id(6, None)
        require(context, "test keygen context allocation failed")
        key = C.c_void_p()
        try:
            require(self.lib.EVP_PKEY_keygen_init(context) == 1, "test keygen init failed")
            require(self.lib.EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) == 1, "test RSA size failed")
            require(self.lib.EVP_PKEY_keygen(context, C.byref(key)) == 1 and key.value, "test key generation failed")
        finally:
            self.lib.EVP_PKEY_CTX_free(context)
        self.ephemeral.append(key.value)
        n, e = C.c_void_p(), C.c_void_p()
        try:
            require(self.lib.EVP_PKEY_get_bn_param(key, b"n", C.byref(n)) == 1, "public modulus unavailable")
            require(self.lib.EVP_PKEY_get_bn_param(key, b"e", C.byref(e)) == 1, "public exponent unavailable")
            nb, eb = C.create_string_buffer(256), C.create_string_buffer(4)
            require(self.lib.BN_bn2binpad(n, nb, 256) == 256, "public modulus length differs")
            require(self.lib.BN_bn2binpad(e, eb, 4) == 4, "public exponent length differs")
            require(int.from_bytes(eb.raw, "big") == 65537, "unexpected test public exponent")
            return key.value, nb.raw
        finally:
            if n.value:
                self.lib.BN_free(n)
            if e.value:
                self.lib.BN_free(e)

    def sign_digest(self, key, digest):
        require(len(digest) == 32, "test digest length differs")
        context = self.lib.EVP_PKEY_CTX_new(key, None)
        require(context, "test signing context allocation failed")
        try:
            require(self.lib.EVP_PKEY_sign_init(context) == 1, "test signing init failed")
            require(self.lib.EVP_PKEY_CTX_set_rsa_padding(context, 6) == 1, "test PSS padding failed")
            require(self.lib.EVP_PKEY_CTX_set_signature_md(context, self.lib.EVP_sha256()) == 1, "test SHA256 failed")
            require(self.lib.EVP_PKEY_CTX_set_rsa_mgf1_md(context, self.lib.EVP_sha256()) == 1, "test MGF1 SHA256 failed")
            require(self.lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(context, 8) == 1, "test salt length failed")
            n = C.c_size_t(0)
            data = C.create_string_buffer(digest)
            require(self.lib.EVP_PKEY_sign(context, None, C.byref(n), data, 32) == 1 and n.value == 256, "test signature size failed")
            signature = C.create_string_buffer(256)
            require(self.lib.EVP_PKEY_sign(context, signature, C.byref(n), data, 32) == 1 and n.value == 256, "test signature failed")
            return signature.raw
        finally:
            self.lib.EVP_PKEY_CTX_free(context)

    def close(self):
        for key in self.ephemeral:
            self.lib.EVP_PKEY_free(key)
        self.ephemeral.clear()


class Replay:
    """Only allowlisted external calls can be serviced; all others abort."""
    def __init__(self, crypto, elf, image):
        self.crypto, self.elf, self.image = crypto, elf, image
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.handles, self.next_handle = {}, 0x06000000
        self.objects = {"rsa": set(), "bn": set(), "key": set(), "mdctx": set(), "pctx": set()}
        self.assigned_rsa, self.assigned_bn = set(), set()
        self.md_info, self.calls, self.digests, self.logs = {}, [], [], []
        self.instruction_count, self.error, self.returned = 0, None, False
        self._map_elf()
        self.uc.mem_map(CAP_BASE, (len(image) + 4095) & ~4095)
        self.uc.mem_write(CAP_BASE, bytes(image))
        self.uc.mem_map(STACK_BASE, STACK_SIZE)
        self.uc.mem_map(HALT, 4096)
        self.uc.mem_write(HALT, bytes.fromhex("1eff2fe1"))
        self.uc.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 16)
        self.uc.reg_write(UC_ARM_REG_LR, HALT)
        self.uc.hook_add(UC_HOOK_CODE, self._code)
        self.uc.hook_add(UC_HOOK_MEM_INVALID, self._invalid)

    def _map_elf(self):
        data = self.elf.data
        phoff = struct.unpack_from("<I", data, 28)[0]
        phsize, phnum = struct.unpack_from("<HH", data, 42)
        loads = [struct.unpack_from("<8I", data, phoff + i * phsize) for i in range(phnum)]
        loads = [p for p in loads if p[0] == 1]
        maximum = max(p[2] + p[5] for p in loads)
        self.uc.mem_map(BASE, (maximum + 4095) & ~4095)
        for _, offset, va, _, filesz, _, _, _ in loads:
            self.uc.mem_write(BASE + va, data[offset:offset + filesz])
        for va, relocation in self.elf.relocations.items():
            if relocation["type"] == 23:
                raw = self.u32(BASE + va)
                self.write32(BASE + va, raw + BASE)
            elif relocation["type"] == 2 and relocation["symbol_defined"]:
                raw = self.u32(BASE + va)
                self.write32(BASE + va, raw + BASE + relocation["symbol_va"])
        self.plt = {BASE + address: name for address, name in self.elf.plt.items()}

    def u32(self, address):
        return int.from_bytes(self.uc.mem_read(address, 4), "little")

    def write32(self, address, value):
        self.uc.mem_write(address, (value & 0xffffffff).to_bytes(4, "little"))

    def string(self, address):
        out = bytearray()
        for index in range(512):
            x = self.uc.mem_read(address + index, 1)[0]
            if x == 0:
                return out.decode("ascii")
            out.append(x)
        raise RuntimeError("unterminated emulated string")

    def new_handle(self, kind, value, owned=True):
        require(value, "native crypto allocation returned NULL: " + kind)
        self.next_handle += 16
        self.handles[self.next_handle] = (kind, int(value))
        if owned:
            self.objects[kind].add(int(value))
        return self.next_handle

    def native(self, handle, expected):
        require(handle in self.handles and self.handles[handle][0] == expected, "unexpected emulated crypto handle type")
        return self.handles[handle][1]

    def capsule_bytes(self, address, length):
        require(0 <= length <= len(self.image) and CAP_BASE <= address <= CAP_BASE + len(self.image) - length, "out-of-capsule crypto input")
        return bytes(self.uc.mem_read(address, length))

    def _invalid(self, uc, access, address, size, value, user):
        self.error = {"reason": "unmapped emulated memory", "access": access, "address": hex(address), "size": size}
        return False

    def _code(self, uc, address, size, user):
        try:
            self.instruction_count += 1
            if address == HALT:
                self.returned = True
                uc.emu_stop()
                return
            if address in self.plt:
                name = self.plt[address]
                args = [uc.reg_read(reg) for reg in REGS]
                caller = uc.reg_read(UC_ARM_REG_LR) - 4
                self.calls.append({"function": name, "caller_elf_va": hex(caller - BASE)})
                result = self.external(name, args)
                uc.reg_write(UC_ARM_REG_R0, result & 0xffffffff)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
            require(BASE + 0x241c <= address < BASE + 0x2880, "execution outside approved PDK code range")
        except Exception as exc:
            self.error = {"reason": type(exc).__name__, "detail": str(exc), "pc": hex(address)}
            uc.emu_stop()

    def external(self, name, args):
        a, b, c, d = args
        lib = self.crypto.lib
        if name == "read_file_append":
            require(self.string(a) == "/var/biossig.bin" and self.string(b) == "/var/bios.bin", "unexpected file input path")
            require(len(self.image) in (0x02001000, 0x04001000), "unaccepted input length")
            self.write32(c, CAP_BASE)
            self.write32(d, len(self.image))
            return 0
        if name in ("printf", "puts"):
            self.logs.append(self.string(a).replace("%ld", str(b)))
            return 1
        if name == "free":
            require(a in (0, CAP_BASE), "unexpected free pointer")
            return 0
        if name == "unlink":
            require(self.string(a) == "/var/biossig.bin", "unexpected unlink path")
            return 0
        if name == "RSA_new":
            return self.new_handle("rsa", lib.RSA_new())
        if name == "BN_bin2bn":
            require(c == 0 and b in (3, 256), "unexpected public BN input")
            if b == 256:
                require(a - CAP_BASE in (0x258, 0x48), "unexpected RSA modulus source")
                data = self.capsule_bytes(a, b)
            else:
                require(STACK_BASE <= a < STACK_BASE + STACK_SIZE - 3, "unexpected exponent source")
                data = bytes(self.uc.mem_read(a, b))
                require(data == b"\x01\x00\x01", "unexpected RSA exponent")
            buffer = C.create_string_buffer(data)
            return self.new_handle("bn", lib.BN_bin2bn(buffer, b, None))
        if name == "RSA_set0_key":
            require(d == 0, "unexpected private key passed by target")
            rsa, n, e = self.native(a, "rsa"), self.native(b, "bn"), self.native(c, "bn")
            result = lib.RSA_set0_key(rsa, n, e, None)
            if result == 1:
                self.assigned_bn.update((n, e))
            return result
        if name == "EVP_PKEY_new":
            return self.new_handle("key", lib.EVP_PKEY_new())
        if name == "EVP_PKEY_assign":
            require(b == 6, "unexpected EVP key algorithm")
            rsa = self.native(c, "rsa")
            result = lib.EVP_PKEY_assign(self.native(a, "key"), b, rsa)
            if result == 1:
                self.assigned_rsa.add(rsa)
            return result
        if name == "EVP_MD_CTX_new":
            h = self.new_handle("mdctx", lib.EVP_MD_CTX_new())
            self.md_info[h] = {"sha256": hashlib.sha256(), "updates": []}
            return h
        if name == "EVP_PKEY_CTX_new":
            require(b == 0, "unexpected crypto engine")
            return self.new_handle("pctx", lib.EVP_PKEY_CTX_new(self.native(a, "key"), None))
        if name == "EVP_sha256":
            return self.new_handle("md", lib.EVP_sha256(), owned=False)
        if name == "EVP_DigestVerifyInit":
            require(d == 0, "unexpected EVP engine")
            key_handle = self.u32(self.uc.reg_read(UC_ARM_REG_SP))
            pcontext = C.c_void_p()
            result = lib.EVP_DigestVerifyInit(self.native(a, "mdctx"), C.byref(pcontext), self.native(c, "md"), None, self.native(key_handle, "key"))
            if result == 1:
                self.write32(b, self.new_handle("pctx", pcontext.value, owned=False))
            return result
        if name == "RSA_pkey_ctx_ctrl":
            final_arg = self.u32(self.uc.reg_read(UC_ARM_REG_SP))
            require((b, c, d, final_arg) == (0xffffffff, 0x1001, 6, 0), "unexpected PDK RSA control")
            return lib.RSA_pkey_ctx_ctrl(self.native(a, "pctx"), -1, c, d, None)
        if name == "EVP_DigestUpdate":
            data = self.capsule_bytes(b, c)
            buffer = C.create_string_buffer(data)
            result = lib.EVP_DigestUpdate(self.native(a, "mdctx"), buffer, c)
            self.md_info[a]["sha256"].update(data)
            self.md_info[a]["updates"].append({"capsule_offset": hex(b - CAP_BASE), "bytes": c})
            return result
        if name == "EVP_DigestVerifyFinal":
            require(c == 256 and b - CAP_BASE in (0x358, 0x148), "unexpected signature source")
            signature = self.capsule_bytes(b, c)
            buffer = C.create_string_buffer(signature)
            result = lib.EVP_DigestVerifyFinal(self.native(a, "mdctx"), buffer, c)
            item = self.md_info[a]
            digest = item["sha256"].digest()
            block_start = 0x248 if b - CAP_BASE == 0x358 else 0x38
            reference = capsule.rsa_pss_sha256(bytes(self.image[block_start:block_start + 528]), digest)
            require((result == 1) == reference["valid"], "native EVP and independent Python PSS disagree")
            self.digests.append({"stage": "certificate" if block_start == 0x248 else "firmware", "digest_sha256": digest.hex(), "updates": item["updates"], "openssl_result": result, "python_pss_valid": reference["valid"], "signature_sha256": sha(signature), "modulus_sha256": reference["modulus_sha256"]})
            return result
        if name == "EVP_MD_CTX_free":
            value = self.native(a, "mdctx")
            lib.EVP_MD_CTX_free(value)
            self.objects["mdctx"].remove(value)
            return 0
        raise RuntimeError("external call is not allowlisted: " + name)

    def close(self):
        lib = self.crypto.lib
        for value in self.objects["mdctx"]:
            lib.EVP_MD_CTX_free(value)
        for value in self.objects["pctx"]:
            lib.EVP_PKEY_CTX_free(value)
        for value in self.objects["key"]:
            lib.EVP_PKEY_free(value)
        for value in self.objects["rsa"] - self.assigned_rsa:
            lib.RSA_free(value)
        for value in self.objects["bn"] - self.assigned_bn:
            lib.BN_free(value)
        for values in self.objects.values():
            values.clear()

    def run(self):
        try:
            self.uc.emu_start(BASE + 0x241c, HALT + 4, timeout=15_000_000, count=100_000)
            require(self.error is None, "emulation stopped on a stub/memory error: " + json.dumps(self.error))
            require(self.returned, "PDK did not return within the instruction/time budget")
            return {"return_u32": self.uc.reg_read(UC_ARM_REG_R0), "returned_to_caller": self.returned, "instruction_hook_count_including_stubs": self.instruction_count, "crypto_stages": self.digests, "messages": self.logs, "external_calls": self.calls, "emulated_unlink_count": sum(c["function"] == "unlink" for c in self.calls), "host_file_unlinks": 0, "stub_or_memory_error": self.error}
        finally:
            self.close()


def main():
    require(not REPORT.exists(), "refusing to overwrite previous replay report")
    original, exp02 = capsule.ORIGINAL.read_bytes(), capsule.CANDIDATE.read_bytes()
    require(sha(original) == capsule.PIN_ORIGINAL and sha(exp02) == capsule.PIN_CANDIDATE, "input capsule pin mismatch")
    elf = elf_module.Elf32(PDK)
    require(sha(elf.data) == PIN_PDK, "PDK ELF pin mismatch")
    symbol = next(s for s in elf.symbols if s["name"] == "PDK_VerifyBiosSignature" and s["section_index"])
    require((symbol["va"], symbol["size"]) == (0x241c, 1192), "PDK symbol bounds mismatch")
    crypto = Crypto()
    results = []
    ephemeral_public_keys = []
    try:
        broken = bytearray(original)
        broken[0x358] ^= 1
        cases = [("original_official_capsule", original, 0, [True, True]), ("exp02_retained_old_signatures", exp02, 1, [True, False]), ("original_certificate_signature_bit_flip", broken, 1, [False])]
        for name, data, expected, stages in cases:
            result = Replay(crypto, elf, data).run()
            require(result["return_u32"] == expected, "unexpected PDK result: " + name)
            require([x["openssl_result"] == 1 for x in result["crypto_stages"]] == stages, "unexpected signature stage result: " + name)
            results.append({"case": name, "input_sha256": sha(data), "expected_return_u32": expected, "passed_expectation": True, **result})
        temporary = bytearray(exp02)
        root_key, root_modulus = crypto.keygen()
        signer_key, signer_modulus = crypto.keygen()
        require(root_modulus != original[0x258:0x358] and signer_modulus != original[0x48:0x148], "test keys unexpectedly match vendor keys")
        ephemeral_public_keys = [{"role": "certificate", "modulus_sha256": sha(root_modulus), "rsa_bits": 2048, "public_exponent": 65537}, {"role": "firmware", "modulus_sha256": sha(signer_modulus), "rsa_bits": 2048, "public_exponent": 65537}]
        temporary[0x258:0x358] = root_modulus
        temporary[0x48:0x148] = signer_modulus
        header = capsule.parse_capsule(temporary)
        temporary[0x148:0x248] = crypto.sign_digest(signer_key, capsule.firmware_digest(temporary, header))
        temporary[0x358:0x458] = crypto.sign_digest(root_key, hashlib.sha256(temporary[0x20:0x248]).digest())
        require(temporary[0x1000:] == exp02[0x1000:], "test variant modified firmware body")
        result = Replay(crypto, elf, temporary).run()
        require(result["return_u32"] == 0, "ephemeral test-key PDK result is not success")
        require([x["openssl_result"] == 1 for x in result["crypto_stages"]] == [True, True], "ephemeral test-key stage mismatch")
        results.append({"case": "exp02_two_ephemeral_test_keys_memory_only", "input_sha256": sha(temporary), "expected_return_u32": 0, "passed_expectation": True, "firmware_body_exactly_exp02": True, "persisted_capsule": False, **result})
        temporary[:] = bytes(len(temporary))
        del temporary
    finally:
        crypto.close()
    report = {
        "schema": "sage1904-pdk-arm-local-trust-replay/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "PASS_FOUR_PINNED_LOCAL_FUNCTION_CASES",
        "scope": "Unicorn executes the PDK ARM function only. External crypto calls run in already-installed host OpenSSL; filesystem/console/free/unlink are closed stubs. This is not native execution of the BMC OS or whole update chain.",
        "inputs": {"original": artifact(capsule.ORIGINAL), "exp02": artifact(capsule.CANDIDATE), "pdk": artifact(PDK), "host_crypto": artifact(LIBCRYPTO), "python_reference_verifier": artifact(Path(capsule.__file__)), "elf_parser": artifact(Path(elf_module.__file__)), "replay_script": artifact(Path(__file__))},
        "runtime": {"python": sys.version.split()[0], "unicorn": unicorn.__version__, "host_openssl": crypto.lib.OpenSSL_version(0).decode("ascii"), "arm_mode": "ARM32 little-endian", "elf_load_bias": hex(BASE), "function_elf_va": "0x241c", "function_mapped_va": hex(BASE + 0x241c), "symbol_bytes": symbol["size"], "symbol_bytes_sha256": sha(elf.data[elf.offset(0x241c):elf.offset(0x241c) + symbol["size"]]), "allowed_instruction_elf_range": "[0x241c,0x2880)", "instruction_limit_per_case": 100000, "unicorn_timeout_microseconds": 15000000},
        "stub_contracts": {"read_file_append": "Only the two expected staging paths are accepted. Supplies the pinned or RAM-only test bytes after validating supported total length; does not execute file helper or read target files.", "crypto": "Typed pointers bridge ARM handles to native OpenSSL public RSA/EVP objects. No forced successful signature results. Each VerifyFinal also runs the independently validated Python RSA-PSS/SHA256 verifier and must agree.", "EVP_DigestUpdate": "Reads only within the emulated capsule buffer. Records each offset and length, and independently hashes the same bytes.", "console": "Captures fixed PDK messages into the report without terminal output from target code.", "free": "Accepts only NULL or the emulated capsule pointer; no host memory pointer is accepted.", "unlink": "Only records the expected /var/biossig.bin cleanup; never removes a host file.", "unexpected_calls_or_memory": "Abort; no permissive default stub exists.", "crypto_api_bindings": crypto.bound_names},
        "ephemeral_test_keys": {"private_keys_exported": False, "private_keys_serialized": False, "private_keys_written": False, "private_keys_logged": False, "key_material_storage": "Native OpenSSL EVP_PKEY handles only; explicitly EVP_PKEY_free after cases. EVP_PKEY_get_bn_param is called only with public parameter names n/e; no private parameter is requested.", "public_identifiers": ephemeral_public_keys, "signing_parameters": "RSA-2048, e=65537, PSS SHA256/MGF1-SHA256, salt length 8", "capsule_written_or_published": False},
        "cases": results,
        "conclusion": "The pinned PDK function returns success for the original CAP and for EXP02 carrying two new ephemeral input-provided public keys with internally consistent signatures; it rejects EXP02's retained old firmware signature and a damaged certificate signature. This validates the local embedded-key trust-boundary observation under the recorded stub contracts.",
        "limitations": ["The file reconstruction helper, shared-library loader/wrapper, REST/auth hooks, BMC runtime configuration, SPI operations, optional VerifyImageSign resident-key branch, firmware boot and CPU policy were not emulated.", "Host OpenSSL 4.0.2 implements imported crypto calls, not the exact BMC libcrypto build. RSA-PSS results are cross-checked with the existing independent Python verifier for these four cases.", "The test does not prove that a self-signed CAP would be accepted by the complete update flow, written successfully, boot successfully, or be remotely recoverable.", "No BMC endpoint, IPMI operation, upload, signing-key installation or firmware write occurred."],
        "effects": {"network_requests": 0, "bmc_requests": 0, "target_firmware_writes": 0, "capsule_files_created": 0, "private_key_files_created": 0, "published_package_changes": 0, "report_only_output": str(REPORT)},
    }
    REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(REPORT), "sha256": sha(REPORT.read_bytes()), "status": report["status"], "results": [{"case": x["case"], "return_u32": x["return_u32"], "stages": [s["openssl_result"] for s in x["crypto_stages"]]} for x in results]}))


if __name__ == "__main__":
    main()
