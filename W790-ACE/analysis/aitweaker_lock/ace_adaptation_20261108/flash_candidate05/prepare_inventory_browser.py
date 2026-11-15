"""Copy the reviewed, no-firmware-upload KVM runner into a fresh evidence folder."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'bmc_hardware03'
OUT = HERE / 'bmc_inventory01'
assert not OUT.exists(), 'Do not overwrite an earlier BMC session'
(OUT / 'operations').mkdir(parents=True)
files = ['bmc_browser.mjs'] + ['operations/' + name + '.mjs' for name in (
    'power_control', 'kvm_key', 'boot_menu_watch', 'session_monitor', 'finish_session',
    'redfish_basic', 'cleanup_snapshot', 'refresh_viewer', 'close_stale_viewer')]
records = []
for name in files:
    source = SOURCE / name
    text = source.read_text(encoding='utf8')
    if name in ('bmc_browser.mjs', 'operations/redfish_basic.mjs'):
        assert text.count('../../../../tools/') == 1
        text = text.replace('../../../../tools/', '../../../../../tools/')
    if name == 'bmc_browser.mjs':
        assert text.count("path.resolve(here,'../../../..')") == 1
        text = text.replace("path.resolve(here,'../../../..')", "path.resolve(here,'../../../../..')")
        text = text.replace("['F2','F8','F10','Delete'", "['F2','F8','Delete'")
    dest = OUT / name
    dest.write_text(text, encoding='utf8')
    records.append({'path': name, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                    'sha256': hashlib.sha256(dest.read_bytes()).hexdigest()})
(OUT / 'runner-source-binding.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf8')
print(json.dumps({'folder': str(OUT), 'files': records}, indent=2))
