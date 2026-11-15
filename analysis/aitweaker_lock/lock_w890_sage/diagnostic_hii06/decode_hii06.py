"""Strict HII06 fingerprint interpretation after the unchanged P3 QR decoder.
Every record is untrusted diagnostic data. This tool never authorizes a page.
"""
from pathlib import Path
import argparse,hashlib,json,re,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LEGACY=ROOT/'analysis/aitweaker_lock/probe_p3_kvm';sys.path.insert(0,str(LEGACY))
from decode_captures import assemble,read_image
HEX=r'[0-9A-F]';GUID=rf'{HEX}{{8}}-{HEX}{{4}}-{HEX}{{4}}-{HEX}{{4}}-{HEX}{{12}}';DIG=rf'{HEX}{{64}}'
F=re.compile(rf'F6 H=({HEX}{{16}}) G=({GUID}) P=({HEX}{{4}}) L=({HEX}{{8}}) S=({DIG})')
M=re.compile(rf'M6 I=({HEX}{{16}}) B=({HEX}{{16}}) Z=({HEX}{{8}}) G=({GUID}|NONFV) T=({HEX}{{8}}):({HEX}{{8}}) R=({DIG}|-) N=({DIG}|-) C=(MATCH|HEADER|RANGE|ALLOC|LAYOUT|RELOC_RANGE|RELOC_TABLE|RELOC_VALUE|MISMATCH|UNKNOWN|FREE|CHANGED)')
COUNTS=re.compile(rf'H6.RECORDS=({HEX}{{8}})({HEX}{{8}})')
def analyze(data):
 if len(data)>65536 or not data.startswith(b'AITWEAKER-PROBE-P3-KVM\r\n') or not data.endswith(b'PROBE_COMPLETE\r\n'):raise ValueError('Incomplete or wrong P3 envelope')
 text=data.decode('ascii');lines=text.split('\r\n')
 if lines.count('HII06_FINGERPRINTS_DIAGNOSTIC_NOT_AUTHORITY')!=1:raise ValueError('Not exactly one HII06 collection')
 catalog=json.loads((HERE.parent/'foreign_hii05/catalog.json').read_text());baseline={p['package_list_guid'].upper():p for p in catalog['packages']}
 profiles=json.loads((HERE/'build/profiles.json').read_text());by_guid={p['guid'].upper():p for p in profiles}
 forms=[];modules=[];seen_f=set();seen_m=set();counts=[];additional=0
 for line in lines:
  if line.startswith('F6 '):
   match=F.fullmatch(line)
   if not match:raise ValueError('Malformed F6 record')
   h,g,index,n,sha=match.groups();index=int(index,16);n=int(n,16)
   if n<4 or n>16*1024*1024 or (h,index) in seen_f:raise ValueError('Duplicate or invalid forms record')
   seen_f.add((h,index));p=baseline.get(g);known=p['forms_packages'] if p else []
   expected=known[index] if index<len(known) else None
   equal=expected is not None and expected['bytes']==n and expected['sha256'].upper()==sha
   forms.append({'handle':h,'package_list_guid':g,'package_index':index,'bytes':n,'sha256':sha.lower(),
                 'baseline_match':equal,'baseline_known':expected is not None,
                 'requires_bytes_or_delta':not equal,'authorization':False})
  elif line.startswith('M6 '):
   match=M.fullmatch(line)
   if not match:raise ValueError('Malformed M6 record')
   i,b,z,g,tr,tn,raw,norm,status=match.groups()
   if i in seen_m:raise ValueError('Duplicate module handle')
   seen_m.add(i);p=by_guid.get(g)
   if status=='MATCH' and (p is None or norm.lower()!=p['text_sha256'] or int(tr,16)!=p['text_rva'] or int(tn,16)!=p['text_size'] or raw=='-'):raise ValueError('Claimed MATCH inconsistent with local original')
   if status=='UNKNOWN' and norm!='-':raise ValueError('Unknown image cannot have a trusted normalized digest')
   modules.append({'loaded_image_handle':i,'base':b,'image_bytes':int(z,16),'reported_ffs_guid':g,
                   'text_rva':int(tr,16),'text_bytes':int(tn,16),'raw_sha256':None if raw=='-' else raw.lower(),
                   'normalized_sha256':None if norm=='-' else norm.lower(),'comparison':status,'authorization':False})
  elif line.startswith('H6.RECORDS='):
   match=COUNTS.fullmatch(line)
   if not match:raise ValueError('Malformed count')
   counts.append(tuple(int(x,16) for x in match.groups()))
  if line.startswith(('M6 ','F6 ','C6 ','D6 ','L6 ')):additional+=len(line)+2
 if len(counts)!=1:raise ValueError('Missing or repeated counts')
 overflow='H6.EXTRA=OVER_BUDGET_PARTIAL' in lines
 if not overflow and counts[0]!=(len(modules),len(forms)):raise ValueError('Record count mismatch')
 if additional>8192:raise ValueError('Extra fingerprint records exceed collector budget')
 unknown=[f for f in forms if f['package_list_guid'].startswith('25FD9F0B-')]
 return {'status':'DIAGNOSTIC_ONLY_NO_RUNTIME_AUTHORITY','log_bytes':len(data),'log_sha256':hashlib.sha256(data).hexdigest(),
         'fingerprint_record_bytes':additional,'collector_partial':'COLLECTION_STATUS=PARTIAL' in lines,
         'fingerprint_budget_overflow':overflow,'reported_counts':counts[0],
         'forms':forms,'modules':modules,'unknown_25fd_instances':unknown,
         'null_driver_observations':[s for s in lines if s.startswith('C6 ')],
         'range_or_service_observations':[s for s in lines if s.startswith(('L6 ','H6.MAP=','M6=','F6='))],
         'notes':['HII handles identify only this collection, not persistent native ownership.','A matching fingerprint is not a signature, publisher proof, or permission to navigate/write.','Raw forms bytes, variable values and password buffers were not exported.']}
def write_new(path,data):
 if path.exists():
  if path.read_bytes()!=data:raise FileExistsError(path)
 else:
  path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb') as f:f.write(data)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('inputs',nargs='+');parser.add_argument('--text-log',action='store_true');parser.add_argument('--output',required=True);a=parser.parse_args()
 if a.text_log:
  if len(a.inputs)!=1:raise ValueError('One text log required')
  data=Path(a.inputs[0]).read_bytes()
 else:
  paths=[]
  for value in a.inputs:
   p=Path(value);paths.extend(sorted(p.glob('*.png')) if p.is_dir() else [p])
  data,_=assemble([read_image(p) for p in paths])
 result=analyze(data);dest=Path(a.output);write_new(dest,json.dumps(result,ensure_ascii=False,indent=2).encode('utf-8')+b'\n');write_new(dest.with_suffix('.log.txt'),data)
 print(json.dumps({'output':str(dest),'forms':len(result['forms']),'modules':len(result['modules']),'bytes':len(data),'status':result['status']},indent=2))
if __name__=='__main__':main()
