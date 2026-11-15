"""Apply the separately recorded SAGE mapping to owned adapter sources only."""
from pathlib import Path
import json,re,hashlib
HERE=Path(__file__).resolve().parent
MAP={0xe208:0xe1b8,0xe21a:0xe1ca,0x15370:0x15320,0x1537f:0x1532f,
 0x16ae0:0x16a90,0x16c70:0x16c20,0x121b8:0x12168,0x1200c:0x11fbc,
 0x62bc:0x626c,0x34b7c:0x34b2c,0x1701c:0x16fcc,0x17040:0x16ff0,
 0x17206:0x171b6,0xe6f4:0xe6a4,0xe70d:0xe6bd,
 0x82748:0x83588,0x92270:0x930b0,0x92b08:0x93948,0x82628:0x83468,
 0x6af78:0x6b928,0x6af80:0x6b930,0x6ae90:0x6b840,0x7cb30:0x7d4f8,
 0x82998:0x837d8,0x824c8:0x83308,
 0x92b10:0x93950,0x82630:0x83470,
 0x760c4005:0x8a65ad70,0x69ecf:0x6a87f,0x9e141291:0xe94c541a,0x2746f:0x2793f,
 0x1a4000:0x1a6000}
def main():
 changes=[]
 for relative in ['driver/platform.c','driver/entry.c','driver/verify_adapter.py','lab/native_hooks.py']:
  path=HERE.parent/relative;text=path.read_text(encoding='utf8');before=text
  text=re.sub(r'0x[0-9a-fA-F]+',lambda m:hex(MAP.get(int(m[0],16),int(m[0],16))),text)
  text=text.replace('99ff85060750d39c9e1a861fd29c48726aa0c82f47b1ec7e6c12150836070ec5','531ed4993b27252df7bc9c2104e0b752857868e3e40691707e4e490b362de3b1')
  path.write_text(text,encoding='utf8')
  changes.append({'file':relative,'before_sha256':hashlib.sha256(before.encode()).hexdigest(),'after_sha256':hashlib.sha256(text.encode()).hexdigest()})
 (HERE/'applied_offsets.json').write_text(json.dumps({'map':{hex(k):hex(v) for k,v in MAP.items()},'changes':changes},indent=2),encoding='utf8')
if __name__=='__main__':main()
