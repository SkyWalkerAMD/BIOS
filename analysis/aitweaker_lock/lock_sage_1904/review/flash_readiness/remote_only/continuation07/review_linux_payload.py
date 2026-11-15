"""Parent review of immutable payload and the actual VM screenshot outputs."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib, importlib.util, json, sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
LC = HERE.parent/'linux_capacity_candidate01'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf8'))
manifest = LC/'payload_manifest.json'
assert sha(manifest) == 'd95d73120917924f230c7c819132cb13d7ffb4ca52f2f5c958c00fd25e01746e'
m = read(manifest)
assert m['artifact_count'] == len(m['files']) == 265
paths = set()
for row in m['files']:
    p = (LC/row['path']).resolve()
    assert p.is_relative_to(LC.resolve()) and p not in paths
    paths.add(p)
    assert p.stat().st_size == row['bytes'] and sha(p) == row['sha256'], str(p)
review = read(LC/'payload_review.json')
assert review['production']['initramfs_sha256'] == '3f1e21419c1b0dd82ac0a23d526bfa647084c9f1edcad2f649051283b1ec6989'
sys.path.insert(0, str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import read_image, assemble
spec = importlib.util.spec_from_file_location('lc_decode_parent', LC/'decode_linux_log.py')
decoder = importlib.util.module_from_spec(spec); spec.loader.exec_module(decoder)
vmroot = LC/'vm_tests_final03'
summary = read(vmroot/'summary.json')
assert summary['status'] == 'PASS' and len(summary['cases']) == 9
decoded = []
for item in summary['cases']:
    folder = vmroot/item['case']['id']
    pngs = list(folder.glob('*.png'))
    candidates = []
    for png in pngs:
        try:
            payload, transport = assemble([read_image(png)], require_inventory=False)
            if sha_bytes := hashlib.sha256(payload).hexdigest():
                if sha_bytes == item['log_sha256']:
                    candidates.append((png, payload, transport))
        except ValueError:
            continue
    assert candidates, str(folder)
    png, payload, transport = candidates[-1]
    meaning = decoder.decode(payload, allow_lab=True)
    assert meaning['complete'] and meaning['sha256'] == item['log_sha256']
    decoded.append({'case':item['case']['id'], 'screenshot':str(png),
                    'screenshot_sha256':sha(png), 'transport':transport, 'semantic':meaning})
record = {
    'status':'PASS_PARENT_FROZEN_PAYLOAD_AND_NINE_VM_QR_REVIEW',
    'utc':datetime.now(timezone.utc).isoformat(),
    'manifest_sha256':sha(manifest), 'frozen_bindings_verified':265,
    'review_sha256':sha(LC/'payload_review.json'),
    'source_review':['source/init.c','source/core.c','source/display.c','decode_linux_log.py','design_review.json'],
    'scope':'Manual source review plus hash and screenshot reassembly; does not rerun or replace original compiled/VM tests.',
    'confirmed_boundaries':[
        'Exact board/BIOS before PCI/USB module work; only named xHCI and unique linked USB SG device selected.',
        'No shell, network, sd/sr/ATA/NVMe/MTD/efivarfs in RAM payload; eight named modules only.',
        'Maximum two RC10 ioctls; one repeat only for byte-exact validated initial UNIT ATTENTION 06/29/00.',
        'Both packet outcomes retained; pending marker is distinct from complete; storage-data writes and block reads absent from this probe.',
        'Framebuffer dimensions, stride, offsets and total aperture checked before mapped pixel writes.'
    ],
    'limitations':[
        'Linux performs ordinary device initialization and SCSI scan/recovery independently; ioctl count is not total bus transaction count.',
        'Kernel EFI stub and final ISO handoff are separate validation; fw_cfg results do not prove them.',
        'No physical Linux boot, capacity result, full SPI backup, firmware trust acceptance or release readiness established here.'
    ],
    'decoded_vm_cases':decoded
}
(HERE/'linux_payload_parent_review.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
print(json.dumps({'status':record['status'],'bindings':265,'screenshots':len(decoded)}))
