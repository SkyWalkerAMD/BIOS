from pathlib import Path
import hashlib, json
here=Path(__file__).resolve().parent
sage=here.parents[3]
ops=sage/'remote_172_20_2_162/operations'
source=ops/'power_off_inventory.mjs'
data=source.read_bytes()
assert hashlib.sha256(data).hexdigest()=='0298dcec92a58cc2bdf01209d4d0fb0d172d712b66ec9bfdcb34fdf30b120be0'
text=data.decode()
changes={
 'Restore Off from verified inventory QR; no OS running in this test':'Restore Off from the verified completed RAM-only Linux diagnostic; the installed OS is not running',
 'inventory-before-poweroff-':'linux-before-poweroff-',
 'inventory-poweroff-':'linux-poweroff-',
}
for old,new in changes.items():
    assert text.count(old)==1
    text=text.replace(old,new)
dest=ops/'power_off_linux08.mjs';dest.write_bytes(text.encode())
record={'source':str(source),'source_sha256':hashlib.sha256(data).hexdigest(),
        'output':str(dest),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),
        'changes':changes,'behavior':'Only output filenames and descriptive wording changed; same QR identity and current On check, same power_command0. RAM Linux is an OS; previous no-OS wording must not be reused.'}
(here/'linux_poweroff_delta.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record))
