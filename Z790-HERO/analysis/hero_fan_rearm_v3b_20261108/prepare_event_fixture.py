"""Import the exact, zero-write .71 GET response; never opens a socket."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent
source=P/'fixtures/fan-rearm-v3-01.json';raw=source.read_bytes()
digest=hashlib.sha256(raw).hexdigest()
assert digest=='c5a15fd519c8e2645c61a8c8ba202627ad14d1705b07c27deb56cd7e0630622a'
j=json.loads(raw);events=j['events']
intents=[e for e in events if e['type']=='intent'];result=next(e for e in events if e['type']=='result')
assert len(intents)==result['requests']==7 and not result['sent_writes']
assert not result['candidate_attempted'] and all(not e['write'] and e['retry'] is False for e in intents)
intent=next(e for e in intents if e['label']=='event_enable_before')
assert (intent['netfn'],intent['command'],intent['request_hex'])==(4,0x29,'20')
reply=next(e for e in events if e['type']=='response' and e['sequence']==intent['sequence'])
assert reply['ok'] and reply['completion_code']==0 and reply['response_hex']=='8005000500'
data=bytes.fromhex(reply['response_hex']);h=hashlib.sha256(data).hexdigest()
(P/'fixtures/sensor20-event-enable.bin').write_bytes(data)
info=dict(source=source.name,source_sha256=digest,requests=7,sets=0,netfn='04',command='29',request_hex='20',
 completion_code=0,response_hex=data.hex(),response_bytes=len(data),response_sha256=h,
 correction='Prior model transposed 05 70 to 70 05; actual threshold GET applies 0x0FFF to enabled masks. Exact fixture only, no wildcard acceptance.')
(P/'fixtures/sensor20-event-enable-evidence.json').write_text(json.dumps(info,indent=2)+'\n')
p=P/'fan_rearm_trial.py';s=p.read_text();s=s.replace('PLACEHOLDER_EVENT_HASH',h);p.write_text(s)
print(json.dumps(info,indent=2))
