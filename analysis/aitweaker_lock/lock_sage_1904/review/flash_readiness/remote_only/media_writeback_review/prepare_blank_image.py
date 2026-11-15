"""Create a new bounded local FAT test image, never mount or connect it."""
from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/vm-pydeps').is_dir())
sys.path.insert(0, str(ROOT/'tools/vm-pydeps'))
from pyfatfs.PyFat import PyFat
from pyfatfs.PyFatFS import PyFatFS

out = (HERE/'blank_test/WRITEBACK02.img').resolve()
assert out.is_relative_to(HERE.resolve())
assert not out.exists(), 'Preserve prior test image and baseline'
out.parent.mkdir(parents=True, exist_ok=True)
with out.open('xb'):
    pass
fat = PyFat()
fat.mkfs(str(out), fat_type=16, size=16*1024*1024, label='WBTEST02', volume_id=0x57423032)
fat.close()
marker = b'AI TWEAKER LOCAL WRITEBACK TEST 02\r\nMARKER 39F4B65F-613F-475A-A93F-FA6CB211B002\r\n'
with PyFatFS(str(out), utc=True) as fs:
    fs.writebytes('/IDENTIFY.TXT', marker)
with PyFatFS(str(out), read_only=True, utc=True) as fs:
    assert fs.readbytes('/IDENTIFY.TXT') == marker
    assert fs.listdir('/') == ['IDENTIFY.TXT']
raw = out.read_bytes()
assert len(raw) == 16*1024*1024
assert raw[510:512] == b'\x55\xaa'
report = {
    'status':'PREPARED_LOCALLY_ONLY_NOT_MOUNTED_OR_TESTED_ON_HOST',
    'path':str(out), 'bytes':len(raw), 'sha256_before_test':hashlib.sha256(raw).hexdigest(),
    'format':'FAT16 superfloppy regular file, 512-byte sectors, 16 MiB',
    'label':'WBTEST02', 'volume_id_hex':'57423032',
    'marker_path':'/IDENTIFY.TXT', 'marker_ascii':marker.decode('ascii'),
    'marker_sha256':hashlib.sha256(marker).hexdigest(),
    'future_allowed_test_write':{'path':'/WRBACK.TXT','max_bytes':4096},
    'scope':'A later separately coordinated writeback test may write only a disposable marker to this image. No firmware read, flash write, internal disk access or BMC settings changes.',
    'failed_prior_preparation':'WRITEBACK01.img was a local-only unsuccessful 4 MiB FAT16 mkfs attempt (PyFat chose invalid zero sectors per cluster). It is not a usable test image and was never mounted. Only WRITEBACK02.img is bound by this baseline.',
    'future_acceptance':'Require READ_WRITE mode 0, identify this volume by both label and exact marker before writing, flush/close, disconnect, reopen image locally read-only, compare exact resulting file bytes and image size. A successful SCSI status alone is insufficient.',
    'created_by':str(Path(__file__).resolve()),
    'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
}
(out.parent/'baseline.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
print(json.dumps({'image':str(out), 'sha256':report['sha256_before_test'], 'bytes':len(raw)}))
