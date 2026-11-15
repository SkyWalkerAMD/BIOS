from pathlib import Path
import zipfile,json,struct,hashlib
H=Path(__file__).resolve().parent;Z=H.parent/'integration05/parser-snapshot.zip'
assert hashlib.sha256(Z.read_bytes()).hexdigest()=='4b65d173ec3a9d4a3e8d02aa8d3becbf9ee61abbb688584cc96e18c93f5fdfbb'
with zipfile.ZipFile(Z)as z:
 im=z.read('tse-mapped.bin');s=json.loads(z.read('state.json'))
report={'source_sha256':hashlib.sha256(Z.read_bytes()).hexdigest(),'globals':{hex(r):hex(struct.unpack_from('<Q',im,r)[0])for r in [0xbaac0,0xbaac8,0xbaae8,0xbaaf0,0xbaaf8,0xbab00,0xbab08,0xbabc0,0xafcd8]},'state_keys':list(s),'allocation_structure':{k:(len(v)if isinstance(v,list)else None)for k,v in s.items()}}
(H/'fixture_data.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
