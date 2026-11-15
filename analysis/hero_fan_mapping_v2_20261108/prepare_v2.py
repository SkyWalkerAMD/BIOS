"""Build corrected fixed-SDR revision from independent captured bytes."""
from pathlib import Path
import hashlib
import json
import shutil

P=Path(__file__).resolve().parent
ROOT=P.parents[1]
OLD=ROOT/'analysis/hero_fan_mapping_20261108'
FIX=P/'fixtures'
FIX.mkdir(exist_ok=True)
def sha(b):return hashlib.sha256(b).hexdigest()
entries=[]
for stem,path in (
 ('r3initial',ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-r3-initialized.TXT'),
 ('r3auto',ROOT/'analysis/hero_ipmi_complete_live_20261108/hero71-r3auto-second.TXT'),
):
 raw=path.read_bytes();lines=raw.decode('ascii').splitlines();matches=[]
 for i,line in enumerate(lines[:-1]):
  if line=='TX 0A/23 00 00 22 00 00 FF':
   assert lines[i+1].startswith('RX OK ')
   reply=bytes.fromhex(lines[i+1][6:]);assert reply[:3]==bytes.fromhex('2c2300')
   matches.append((i+1,reply[3:],lines[i+1]))
 assert matches and all(m[1]==matches[0][1] for m in matches)
 reply=matches[0][1];(FIX/f'{stem}-sdr-reply.bin').write_bytes(reply)
 entries.append(dict(source=str(path.relative_to(ROOT)),source_sha256=sha(raw),
     matching_records=len(matches),tx_lines=[m[0] for m in matches],
     rx_lines=[m[2] for m in matches],reply_file=f'{stem}-sdr-reply.bin',
     reply_sha256=sha(reply),reply_hex=reply.hex()))
path=OLD/'fan-map-trial-01.json';raw=path.read_bytes();d=json.loads(raw)
item=next(e for e in d['events'] if e['type']=='response' and e['label']=='target_SDR_before')
assert item['ok'] and item['completion_code']==0
reply=bytes.fromhex(item['response_hex']);(FIX/'trial01-sdr-reply.bin').write_bytes(reply)
entries.append(dict(source=str(path.relative_to(ROOT)),source_sha256=sha(raw),reply_file='trial01-sdr-reply.bin',reply_sha256=sha(reply),reply_hex=reply.hex()))
assert len({e['reply_hex'] for e in entries})==1
record=reply[2:];assert len(record)==5+record[4]==59 and record[:5]==bytes.fromhex('2200510136') and record[7]==0x20
assert sha(record)=='a253da27c190c2973891597bfb1fe61c52c828b420dfb46388916cdcac4784d8'
(FIX/'mb-cha-fan1-sdr.bin').write_bytes(record)
(FIX/'sdr-evidence.json').write_text(json.dumps(dict(record_bytes=59,record_sha256=sha(record),sources=entries),indent=2)+'\n',encoding='utf-8')
shutil.copyfile(path,FIX/'fan-map-trial-01.json')
for name in ('test_fan_map_trial.py','test_vendor_arm.py','prepare_sources.py',
             'build_handoff.py','试验与复原说明.txt','原厂映射分析.txt',
             'arm-verification.json','source-manifest.json'):
 shutil.copyfile(OLD/name,P/name)
for directory in ('probe_runtime','sources','disassembly'):
 for source in (OLD/directory).rglob('*'):
  if source.is_file() and '__pycache__' not in source.parts and source.suffix!='.pyc':
   dest=P/source.relative_to(OLD);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
(P/'rea-hwm').mkdir(exist_ok=True);shutil.copyfile(OLD/'rea-hwm/ended.json',P/'rea-hwm/ended.json')
script=(OLD/'fan_map_trial.py').read_text(encoding='utf-8')
oldline=next(line for line in script.splitlines() if line.startswith('SDR_RECORD='))
script=script.replace(oldline,
 "SDR_RECORD=(P/'fixtures/mb-cha-fan1-sdr.bin').read_bytes()\n"
 "SDR_RECORD_SHA256='a253da27c190c2973891597bfb1fe61c52c828b420dfb46388916cdcac4784d8'\n"
 "if len(SDR_RECORD)!=59 or len(SDR_RECORD)!=5+SDR_RECORD[4] or hashlib.sha256(SDR_RECORD).hexdigest()!=SDR_RECORD_SHA256:\n"
 " raise base.PolicyError('fixed original SDR fixture mismatch')")
script=script.replace("'hero-fan-map-only-1'","'hero-fan-map-only-2'").replace("'hero-fan-map-only-run-1'","'hero-fan-map-only-run-2'")
(P/'fan_map_trial.py').write_text(script,encoding='utf-8')
revision=dict(change='Replace mistranscribed 60-byte SDR constant with exact 59-byte captured fixture; retain byte-for-byte gate.',
    previous_script_sha256=sha((OLD/'fan_map_trial.py').read_bytes()),
    previous_package_sha256=sha((OLD/'HERO-FAN-MAP-ONLY-20261108-REVIEW.zip').read_bytes()),
    previous_length=60,verified_length=59,visible_first_difference_offset=31,
    extra_zero_removal_example_offset=30,original_package_modified=False,
    trial01_sent_writes=[],fixed_record_sha256=sha(record),
    current_script_sha256=sha((P/'fan_map_trial.py').read_bytes()))
(P/'revision.json').write_text(json.dumps(revision,indent=2)+'\n',encoding='utf-8')
print(json.dumps(revision))
