"""Extract complete I3b HTTP evidence from an already CRC-verified log; no I/O to host."""
from pathlib import Path
import argparse, hashlib, json, re, zlib

p = argparse.ArgumentParser()
p.add_argument('log', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
raw = a.log.read_bytes()
assert raw.startswith((b'HERO-INVENTORY-I3B\r\nBUILD=I3B-71-LEGACY-INVENTORY\r\n',
                       b'HERO-INVENTORY-I3D\r\nBUILD=I3D-71-CONTINUATION\r\n'))
text = raw.decode('ascii')
rows = []
for block in re.split(r'(?=PTLS_RESOURCE_ID=0x[0-9A-F]{16}\r\n)', text)[1:]:
    ident = int(re.search(r'PTLS_RESOURCE_ID=0x([0-9A-F]+)', block)[1], 16)
    request = re.search(r'^(GET|PATCH|POST) (\S+) HTTP/1\.1\r?$', block, re.M)
    status = re.search(r'PTLS_HTTP_STATUS=0x([0-9A-F]+)', block)
    exchange = re.search(r'PTLS_HTTP_BEGIN\r\n(.*?)\r\nPTLS_HTTP_END', block, re.S)
    decoded = re.search(r'PTLS_DECODED_BEGIN\r\n(.*?)\r\nPTLS_DECODED_END', block, re.S)
    row = dict(resource_id=ident, method=request[1] if request else None,
               route=request[2] if request else None,
               status=int(status[1],16) if status else None,
               exact_pin_verified='PTLS_HANDSHAKE_EXACT_PIN_AUTHENTICATED' in block)
    body = decoded[1] if decoded else None
    if exchange:
        head, sep, encoded_body = exchange[1].partition('\r\n\r\n')
        assert head.startswith('HTTP/1.1 ')
        if body is None and sep:
            body = encoded_body
    if body == '' and row['status'] == 204:
        row['response_has_no_body'] = True
    elif body is not None:
        try:
            row['body'] = json.loads(body)
        except json.JSONDecodeError:
            row['body_parse_failed'] = True
    rows.append(row)
result = dict(source=a.log.name, bytes=len(raw), crc32=f'{zlib.crc32(raw):08X}',
              sha256=hashlib.sha256(raw).hexdigest(), resources=rows,
              states=re.findall(r'^I3[BD]_(?:INVENTORY_(?:STATE|STEP|DONE_MASK|INDEXED_MASK|PREFLIGHT)|WRITE_[A-Z_]+|SUMMARY_[A-Z_]+|CORE_INVENTORY_READBACK_VERIFIED|PREFLIGHT_[A-Z_]+)[^\r\n]*',text,re.M))
encoded=(json.dumps(result,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
if a.output.exists():
    assert a.output.read_bytes()==encoded, 'Refusing to overwrite different evidence'
else:
    a.output.write_bytes(encoded)
print(json.dumps({**{k:v for k,v in result.items() if k!='resources'},
                  'resources':[{k:v for k,v in r.items() if k!='body'} for r in rows]},indent=2))
