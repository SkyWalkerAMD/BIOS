"""Verify the observed capsule signature chain using installed OpenSSL.

Writes only derived public keys, signatures, hashes, and a report locally.
Never accepts a private key, signs an image, accesses a device, or flashes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path

import verify_capsule_static as capsule


HERE = Path(__file__).resolve().parent
OPENSSL = Path("D:/OpenSSL-Win64/bin/openssl.exe")


def tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 128:
        encoded = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        encoded = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + encoded + value


def public_key_pem(modulus: bytes) -> bytes:
    # PKCS#1 RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    require = capsule.require
    require(len(modulus) == 256 and modulus[0] & 0x80 != 0, "expected RSA-2048 key")
    der = tlv(0x30, tlv(0x02, b"\x00" + modulus) + tlv(0x02, b"\x01\x00\x01"))
    data = base64.b64encode(der)
    return b"-----BEGIN RSA PUBLIC KEY-----\n" + b"\n".join(data[i:i + 64] for i in range(0, len(data), 64)) + b"\n-----END RSA PUBLIC KEY-----\n"


def main() -> None:
    original = capsule.ORIGINAL.read_bytes()
    candidate = capsule.CANDIDATE.read_bytes()
    capsule.require(capsule.sha(original) == capsule.PIN_ORIGINAL, "original binding")
    capsule.require(capsule.sha(candidate) == capsule.PIN_CANDIDATE, "candidate binding")
    oh = capsule.parse_capsule(original)
    ch = capsule.parse_capsule(candidate)
    report_path = HERE / "capsule_static_review.json"
    review = json.loads(report_path.read_text(encoding="utf-8"))
    capsule.require(review["script_sha256"] == capsule.sha(Path(capsule.__file__).read_bytes()), "review script binding")
    work = HERE / "openssl_public_evidence"
    work.mkdir(exist_ok=True)
    for name, offset in (("firmware", 0x38), ("certificate", 0x248)):
        (work / f"{name}.public.pem").write_bytes(public_key_pem(original[offset + 16:offset + 272]))
        (work / f"{name}.signature.bin").write_bytes(original[offset + 272:offset + 528])
    digests = {
        "original_firmware": capsule.firmware_digest(original, oh),
        "exp02_firmware": capsule.firmware_digest(candidate, ch),
        "original_certificate": hashlib.sha256(original[0x20:0x248]).digest(),
        "exp02_certificate": hashlib.sha256(candidate[0x20:0x248]).digest(),
    }
    results = []
    for name, digest in digests.items():
        kind = name.split("_", 1)[1]
        expected = name != "exp02_firmware"
        (work / f"{name}.sha256.bin").write_bytes(digest)
        argv = [
            str(OPENSSL), "pkeyutl", "-verify", "-pubin",
            "-inkey", str(work / f"{kind}.public.pem"),
            "-sigfile", str(work / f"{kind}.signature.bin"),
            "-in", str(work / f"{name}.sha256.bin"),
            "-pkeyopt", "digest:sha256",
            "-pkeyopt", "rsa_padding_mode:pss",
            "-pkeyopt", "rsa_pss_saltlen:8",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ]
        process = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        capsule.require((process.returncode == 0) == expected, "OpenSSL result differs: " + name)
        results.append({
            "name": name,
            "argv": argv,
            "digest": digest.hex(),
            "returncode": process.returncode,
            "signature_valid": process.returncode == 0,
            "expected_valid": expected,
            "stdout": process.stdout.strip(),
            "stderr": process.stderr.strip(),
        })
    version = subprocess.run([str(OPENSSL), "version", "-a"], capture_output=True, text=True, check=True, timeout=30)
    report = {
        "status": "PASS_ALL_FOUR_RESULTS_AGREE_WITH_PURE_PYTHON_VERIFIER",
        "script_sha256": capsule.sha(Path(__file__).read_bytes()),
        "static_review_sha256": capsule.sha(report_path.read_bytes()),
        "original_sha256": capsule.sha(original),
        "candidate_sha256": capsule.sha(candidate),
        "openssl_executable": str(OPENSSL),
        "openssl_executable_sha256": capsule.sha(OPENSSL.read_bytes()),
        "openssl_version_output": version.stdout.strip(),
        "only_public_material_used": True,
        "no_image_mutation_or_device_access": True,
        "checks": results,
        "derived_files": [{"name": p.name, "sha256": capsule.sha(p.read_bytes()), "bytes": p.stat().st_size} for p in sorted(work.iterdir()) if p.is_file()],
    }
    output = HERE / "openssl_signature_crosscheck.json"
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "sha256": capsule.sha(output.read_bytes()), "output": str(output), "results": [{"name": r["name"], "valid": r["signature_valid"]} for r in results]}, indent=2))


if __name__ == "__main__":
    main()
