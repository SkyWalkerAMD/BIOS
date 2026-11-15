from pathlib import Path
import json,uuid,hashlib
H=Path(__file__).resolve().parent;c=json.loads((H/'native_variable_catalog.json').read_text())
rows=[]
for e in c['items']:
 g=uuid.UUID(e['guid']).bytes_le;n=[ord(x) for x in e['name']]
 assert len(n)<40
 rows.append('{ {'+','.join(str(x) for x in g)+'}, {'+','.join(str(x) for x in n+[0])+'}, '+str(e['attributes'])+','+str(e['declared_size'])+' },')
text='/* Exact original descriptor identities; native indices are intentionally absent. */\nstatic const struct {uint8_t guid[16];uint16_t name[40];uint32_t attrs,size;} ws_catalog[]={\n'+'\n'.join(rows)+'\n};\n'
(H/'catalog04.inc').write_text(text,encoding='ascii')
print(json.dumps(dict(count=len(rows),source_sha256=c['source_sha256'],catalog_sha256=hashlib.sha256(text.encode()).hexdigest())))
