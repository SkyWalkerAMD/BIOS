"""Summarize preserved I3 GET evidence; no hardware or network access."""
from pathlib import Path
import argparse, hashlib, json, re, zlib

p = argparse.ArgumentParser()
p.add_argument('log', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
raw = a.log.read_bytes()
assert raw.startswith(b'HERO-INVENTORY-I3\r\nBUILD=I3-71-PINNED-GET-ONLY\r\n')
text = raw.decode('ascii')
rows = []
for block in re.split(r'(?=PTLS_RESOURCE_ID=0x[0-9A-F]{16}\r\n)', text)[1:]:
    ident = int(re.search(r'PTLS_RESOURCE_ID=0x([0-9A-F]+)', block)[1], 16)
    route = re.search(r'^GET (\S+) HTTP/1\.1\r?$', block, re.M)
    status = re.search(r'PTLS_HTTP_STATUS=0x([0-9A-F]+)', block)
    framing = re.search(r'PTLS_HTTP_FRAMING=0x([0-9A-F]+)', block)
    exchange = re.search(r'PTLS_HTTP_BEGIN\r\n(.*?)\r\nPTLS_HTTP_END', block, re.S)
    decoded = re.search(r'PTLS_DECODED_BEGIN\r\n(.*?)\r\nPTLS_DECODED_END', block, re.S)
    row = dict(resource_id=ident, route=route[1] if route else None,
               status=int(status[1], 16) if status else None,
               framing=int(framing[1], 16) if framing else None,
               exact_pin_verified='TLS_HANDSHAKE_EXACT_PIN_AUTHENTICATED' in block)
    if exchange:
        head, sep, body = exchange[1].partition('\r\n\r\n')
        assert head.startswith('HTTP/1.1 ')
        if decoded:
            body = decoded[1]
        if sep or decoded:
            try:
                value = json.loads(body)
                row['body'] = value
            except json.JSONDecodeError:
                row['body_parse_failed'] = True
    rows.append(row)
result = dict(source=a.log.name, bytes=len(raw), crc32=f'{zlib.crc32(raw):08X}',
              sha256=hashlib.sha256(raw).hexdigest(), resources=rows,
              batch_complete='I3_READONLY_INVENTORY_BATCH_COMPLETE' in text)
encoded = (json.dumps(result, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
if a.output.exists():
    assert a.output.read_bytes() == encoded, 'Refusing to overwrite different evidence'
else:
    a.output.write_bytes(encoded)
print(json.dumps({**{k:v for k,v in result.items() if k!='resources'},
                  'resources': [{k:v for k,v in r.items() if k!='body'} for r in rows]}, indent=2))
