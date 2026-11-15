"""Freeze verified live fan data; no sockets or live-device operations."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;f=P/'fixtures/fan-rearm-v3b-01.json';b=f.read_bytes()
assert hashlib.sha256(b).hexdigest()=='e547b8c2fdd3c73350dbfd47b3d006c560dde8876e609072c926c92f76eff03c'
j=json.loads(b);ev=j['events'];r=next(e for e in ev if e['type']=='result')
intents=[e for e in ev if e['type']=='intent'];writes=[e for e in intents if e['write']]
assert len(intents)==r['requests']==170 and len(writes)==4
assert r['sent_writes']==['candidate','hide','unhide','restore']
assert all(e['retry'] is False for e in intents)
assert [(e['netfn'],e['command'],e['request_hex']) for e in writes]==[(48,154,'0101000062'+'00'*12),(48,148,'2000'),(48,148,'2001'),(48,154,'0101'+'00'*15)]
assert [x['raw_hex'] for x in r['samples']]==['17c0c000']*5
assert [x['raw_hex'] for x in r['samples_after_restore']]==['00c0c700']*3
assert r['event_enable_after_restore']=='c005000500' and r['map_restored'] and r['control_tables_restored'] and r['record_set_restored']
assert r['requires_review'] and r['cleanup_error']=='observable_sensor_state_differs_no_more_sets'
reply={e['label']:e for e in ev if e['type']=='response'}
rows={}
for label in ('SDR_before','SDR_after'):
 parsed={}
 for i in range(58):
  e=reply[label+'_record_'+str(i)];d=bytes.fromhex(e['response_hex']);assert e['completion_code']==0 and len(d)==d[6]+7
  record=d[2:];rid=int.from_bytes(record[:2],'little');assert rid not in parsed;parsed[rid]=record
 assert len(parsed)==58
 assert hashlib.sha256(b''.join(parsed[k] for k in sorted(parsed))).hexdigest()=='29d64b1026a67d93d9b7822613fa4b7ebd5f2b5525c9d921f475d67ec97b65c5'
 if rows:assert rows==parsed
 rows=parsed
catalog=dict(count=58,record_bytes_sha256='29d64b1026a67d93d9b7822613fa4b7ebd5f2b5525c9d921f475d67ec97b65c5',records={str(k):rows[k].hex() for k in sorted(rows)})
(P/'fixtures/sdr-records.json').write_text(json.dumps(catalog,indent=2)+'\n')
assert rows[0x22]==(P/'fixtures/mb-cha-fan1-sdr.bin').read_bytes()
for sub,expected in enumerate((b'\0',bytes(15),bytes(15),bytes([1])*15)):
 e=reply['restore_verify_'+str(sub)];assert e['completion_code']==0 and bytes.fromhex(e['response_hex'])==expected
for filename,data in [('reading-current.bin',bytes.fromhex('00c0c700')),('event-current.bin',bytes.fromhex('c005000500'))]:
 (P/'fixtures'/filename).write_bytes(data)
summary=dict(schema='hero-fan-live-evidence-1',source=f.name,source_sha256=hashlib.sha256(b).hexdigest(),requests=170,sets=4,
 positive_readings=r['samples'],reading_after_zero_map=r['samples_after_restore'],event_after_zero_map=r['event_enable_after_restore'],
 raw_SDR_unchanged=True,SDR_count=58,SDR_record_bytes_sha256=catalog['record_bytes_sha256'],
 all_control_arrays_restored=True,observable_state_restored=False,
 conclusion='Source62 for target20 produced five valid 2760RPM samples. Restoring map0 retained scanning and produced 0RPM with changed threshold-state bytes. Keep the verified map when restoring useful operation; do not auto-hide/unhide again.',
 limitations=['BIOS CHA1 2678RPM screenshot was not time-synchronized.','Private scanner state1 is inferred from vendor code and live behavior, not directly read.'],
 fixtures={n:hashlib.sha256((P/'fixtures'/n).read_bytes()).hexdigest() for n in ('sdr-records.json','reading-current.bin','event-current.bin')})
(P/'live-evidence.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary['fixtures'],indent=2))
