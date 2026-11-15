"""Reuse local audited display/ABI code; all writes stay inside this new folder."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'analysis/hero_ipmi_p6_20261104/collector'
copied = []
for name in ['efi_min.h', 'kvm.h', 'kvm.c', 'compat/assert.h', 'compat/stdlib.h',
             'compat/string.h', 'vendor/qrcodegen.c', 'vendor/qrcodegen.h']:
    src = OLD / 'source' / name
    dest = HERE / 'source' / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = src.read_bytes()
    if name == 'kvm.c':
        data = data.replace(b'278528', b'786432')
        data = data.replace(b'HERO-IPMI-P6-QR1', b'HERO-SMBIOS-I1-QR1')
        data = data.replace(b'HERO P6 RC4 AUDIT', b'HERO SMBIOS I1')
    dest.write_bytes(data)
    copied.append({'source': str(src.relative_to(ROOT)), 'target': name,
                   'source_sha256': hashlib.sha256(src.read_bytes()).hexdigest(),
                   'result_sha256': hashlib.sha256(data).hexdigest()})

script = (OLD / 'build.py').read_text(encoding='utf-8')
script = script.replace('ROOT=P.parents[2]', 'ROOT=P.parents[1]')
script = script.replace("('common','launcher','kvm','vendor/qrcodegen')", "('common','smbios','launcher','kvm','vendor/qrcodegen')")
script = script.replace("('launcher','common','kvm','qrcodegen')", "('launcher','smbios','common','kvm','qrcodegen')")
script = script.replace("'/export:kvm_make_frame'", "'/export:smbios_entry','/export:smbios_table','/export:kvm_make_frame'")
script = script.replace("('common','kvm','qrcodegen')", "('smbios','common','kvm','qrcodegen')")
script = script.replace('HERO_P6.TAG', 'HERO_INV.TAG').replace('HERO-IPMI-P6-LOG', 'HERO-SMBIOS-I1')
script = script.replace('HERO-P6-RC4-READONLY-LOG.iso', 'HERO-SMBIOS-I1-READONLY.iso')
script = script.replace('HERO_P6_RC4_AUDIT', 'HERO_SMBIOS_I1')
script = script.replace('P6 RC4 AUDIT / CAPTURE ONLY', 'SMBIOS I1 / READ ONLY')
script = script.replace('Build only the P6/R2 capture application', 'Build only the SMBIOS capture application')
(HERE / 'build.py').write_text(script, encoding='utf-8')

decoder = (OLD / 'decode_captures.py').read_text(encoding='utf-8')
decoder = decoder.replace('ROOT=OUT.parents[2]', 'ROOT=OUT.parents[1]')
decoder = decoder.replace('HERO-IPMI-P6-QR1', 'HERO-SMBIOS-I1-QR1')
decoder = decoder.replace('278528', '786432').replace('{1,3}', '{1,4}')
decoder = decoder.replace('P6 KVM', 'SMBIOS I1 KVM').replace('P6 QR', 'SMBIOS I1 QR').replace('P6 snapshot', 'SMBIOS I1 snapshot')
start = decoder.index('    complete=')
end = decoder.index('    if require_snapshot', start)
decoder = decoder[:start] + "    complete=data.startswith(b'HERO-SMBIOS-I1\\r\\nRUN=') and data.endswith(b'END SMBIOS SNAPSHOT\\r\\n')\n" + decoder[end:]
(HERE / 'decode_captures.py').write_text(decoder, encoding='utf-8')
(HERE / 'source-provenance.json').write_text(json.dumps(copied, indent=2) + '\n', encoding='utf-8')
print('Prepared ABI, QR, build and decoder dependencies in new directory only.')
