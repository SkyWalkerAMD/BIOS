from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
iso=ROOT/'analysis/hero_p6_ramcheck15_s23_20261108/HERO-P6-HOST15-S23.iso'
pin='d1cc353b8180b3ddf7fa2b28c6f305a449f54ab5b32c1516852bffba708284d9'
assert hashlib.sha256(iso.read_bytes()).hexdigest()==pin
media=HERE/'media.json';records=json.loads(media.read_text())
assert not any(x['id']=='p6s23-host15' for x in records)
records.append(dict(id='p6s23-host15',path=iso.relative_to(ROOT).as_posix(),sha256=pin))
media.write_text(json.dumps(records,indent=2)+'\n')
source=HERE/'harvest_inventory.py';dest=HERE/'harvest_s23.py'
assert not dest.exists()
s=source.read_text()
s=s.replace("'p6ram15','p6a1'","'p6ram15','p6ram15s23','p6a1'")
s=s.replace("if a.kind=='p6a1':", "if a.kind=='p6ram15s23':decoder_path=ROOT/'analysis/hero_p6_ramcheck15_s23_20261108/decode_captures.py'\nif a.kind=='p6a1':")
s=s.replace("str(OUT/'control.py')","str(OUT/'control_press.py')")
# command.py abbreviates browser snapshots; read the immutable response result,
# rather than requiring its console formatting to contain an 'ok' property.
s=s.replace("assert '\"ok\": true' in r.stdout and 'pending' not in r.stdout,r.stdout", "assert 'pending' not in r.stdout,r.stdout\n    response=json.loads((OUT/'responses'/r.stdout.splitlines()[0]).read_text())\n    assert response.get('ok'),response")
dest.write_text(s)
record={'source':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'new':str(dest),'new_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'media_pin':pin,'changes':['native key path','S23 decoder registration','validate saved response envelope']}
(HERE/'s23-session-provenance.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
