"""Offline integrity and timing record from root-collected live captures."""
from pathlib import Path
import hashlib,importlib.util,json,sys,zlib
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
live=ROOT/'analysis/hero_ipmi_complete_live_20261108'
spec=importlib.util.spec_from_file_location('ramcheck2_decoder',ROOT/'analysis/hero_p6_ramcheck2_20261108/decode_captures.py')
decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
rows=[]
for name in ('hero71-p6s21-loaded','hero71-p6s21-after-setup'):
 folder=live/'captures'/name
 raw,meta=decoder.assemble([p.read_bytes() for p in sorted(folder.glob('*.qr.bin'))])
 assert raw==(live/(name+'.TXT')).read_bytes()
 manifest=json.loads((folder/'manifest.json').read_text())
 assert all(meta[k]==manifest[k] for k in ('pages','bytes','crc32','sha256'))
 audit=raw.split(b'BEGIN P6 CACHED AUDIT\r\n',1)[1].split(b'END P6 CACHED AUDIT',1)[0]
 assert b'P6_SETUP_AUTO_REFRESH' not in audit and b'P6_READ_STATUS=' not in audit
 assert b'RAW=0000000A0100000000000000000000000000000000\r\n' in raw
 assert b'HeroIpmiState STATUS=800000000000000E' in raw
 rows.append(dict(name=name,**meta,audit=audit.decode(),settings21_default_preserved=True,state_absent=True))
assert all(x in rows[1]['audit'] for x in ('P6_AMITSE_AFTER_BOOT','P6_READY_TO_BOOT','P6_AMITSE_BEFORE_BOOT'))
rea=ROOT/'analysis/hero_ipmi_p5_rea_review_20261103/amitse/responses/005-setupenter-signal.json'
source=json.loads(rea.read_text())['result']['structuredContent']
assert source['subject']['digest']['sha256']=='f48b8729b53e1bcd196a533576d0b228d2df175c631f314d56623a5a88bcb02c'
report=dict(passed=True,records=rows,rea=dict(path=str(rea.relative_to(ROOT)),sha256=hashlib.sha256(rea.read_bytes()).hexdigest(),evidence_id=source['evidence_id'],functions=source['normalized_result']['items']),conclusion='The exact S21 driver remained resident and its AfterBoot/ReadyToBoot/BeforeBoot notifications executed, but no setup refresh ran. Existing AMITSE evidence shows the SetupEnter marker is transient and its primary publisher is once per image. S21 on_after stops watchdog only. This accounts for the observed late-RAM path gap; it does not prove early native dispatch fails.',next_revision_boundary='A shared bounded refresh-arm helper called after existing on_after stop may cover the returning-app path. No manual refresh API or synthetic event is needed. Actual next revision still requires separate PE and hardware validation.',no_hardware_access_by_reviewer=True)
(OUT/'live-setup-lifecycle.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps(dict(passed=True,records=[{k:v for k,v in row.items() if k!='audit'} for row in rows]),indent=2))
