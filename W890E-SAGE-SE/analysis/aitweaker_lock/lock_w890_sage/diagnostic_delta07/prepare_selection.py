"""Derive an immutable narrow selection from a complete saved HII06 log.
No device access. Without an explicit budget, the result cannot build a carrier.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re
HERE=Path(__file__).resolve().parent;H6=HERE.parent/'diagnostic_hii06'
spec=importlib.util.spec_from_file_location('delta07_hii06_decoder',H6/'decode_hii06.py');h6=importlib.util.module_from_spec(spec);spec.loader.exec_module(h6)
CPU='DBF338FE-93BE-46D6-ADF5-C17C2236D838';UNKNOWN='25FD9F0B-A3EF-4788-A40C-81849D178A6C'
NVME='668706B2-BCFC-4AD4-A185-75E79F3FE169';SOCKET='6B6FD380-2C55-42C6-98BF-CBBC5A9AA666'
from decode_packet import BASELINES
def canonical(value):return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()
def source_relations(data):
 rows={};current=None
 for line in data.decode('ascii').splitlines():
  match=re.fullmatch(r'HII ([0-9A-F-]{36}) handle=0x([0-9A-F]{16}) forms=([0-9]+).*',line)
  if match:current=match[2];rows[current]={'reported_guid':match[1],'forms_count':int(match[3]),'interfaces':[]};continue
  m=re.fullmatch(r'  ConfigAccess\.(ExtractConfig|RouteConfig|Callback) (.*)',line)
  if m and current:rows[current]['interfaces'].append({'method':m[1],'observation':m[2]})
 return rows
def prepare(data,budget_bytes=None):
 decoded=h6.analyze(data)
 if decoded['fingerprint_budget_overflow']:raise ValueError('Source omitted fingerprint records; selection needs complete target inventory')
 selected=[f for f in decoded['forms'] if f['package_list_guid'] in (CPU,NVME,SOCKET,UNKNOWN)]
 cpu=[f for f in selected if f['package_list_guid']==CPU];unknown=[f for f in selected if f['package_list_guid']==UNKNOWN]
 if len(cpu)!=1 or cpu[0]['package_index']!=0:raise ValueError('Expected one CPU forms package at ordinal0; changed structure needs review')
 for guid in (NVME,SOCKET):
  group=[f for f in selected if f['package_list_guid']==guid]
  if len(group)!=1 or group[0]['package_index']!=0:raise ValueError('Expected one reviewed target package at ordinal0: '+guid)
 if len({f['handle'] for f in unknown})!=2:raise ValueError('Expected two distinct unknown HII instances')
 for handle in {f['handle'] for f in unknown}:
  indices=sorted(f['package_index'] for f in unknown if f['handle']==handle)
  if indices!=list(range(len(indices))):raise ValueError('Missing forms package ordinal')
 if budget_bytes is not None and not 1<=budget_bytes<=65536:raise ValueError('Explicit budget must fit P3 64KiB transport')
 relations=source_relations(data);groups={}
 for f in selected:
  key=(f['package_list_guid'],f['package_index'],f['bytes'],f['sha256'])
  groups.setdefault(key,[]).append(f['handle'])
 targets=[];artifact=1
 for key,handles in sorted(groups.items(),key=lambda kv:((CPU,NVME,UNKNOWN,SOCKET).index(kv[0][0]),kv[0])):
  guid,index,n,sha=key;kind=1 if guid==CPU else 2 if guid==UNKNOWN else 3
  target={'kind':kind,'package_list_guid':guid.lower(),'package_index':index,'result_bytes':n,'result_sha256':sha,'expected_instances':len(handles),'artifact_base':artifact,
          'source_hii_handles':sorted(handles),'source_interfaces':{h:relations.get(h) for h in handles},
          'baseline_sha256':BASELINES[guid.lower()][1] if kind!=2 else None,
          'content_remains_unknown':kind==2}
  targets.append(target);artifact+=len(handles)
 payload={'schema':7,'board':'ASUS Pro WS W890E-SAGE SE','bios':'0603','source_log_sha256':hashlib.sha256(data).hexdigest(),
          'hii06_efi_sha256':'c48d89a78c17aba5a975b939bc71ed8d67de2f200abc22f60212fb6b198fc983',
          'targets':targets,'source_module_observations':decoded['modules'],'source_null_driver_observations':decoded['null_driver_observations'],
          'source_nonfv_path_observations':[line for line in data.decode('ascii').splitlines() if line.startswith('D6 ')],
          'qr_budget_bytes':budget_bytes,'runtime_bindings_ready':False,
          'cross_boot_handle_identity':'NOT_ASSUMED; current opaque handles remain distinct; prior equal-content handles are a correlation set only',
          'authorization':False}
 digest=hashlib.sha256(canonical(payload)).hexdigest()
 # Exact upper bound on bytes for the proposed text encoding, using worst-case
 # CPU delta (no matching body bytes) and exact raw lengths. No compression assumed.
 from transport import PREFIX,FOOT
 count=artifact-1;head=PREFIX+f'D7 SOURCE={payload["source_log_sha256"]} SELECTION={digest} PLANNED={count}\r\n'.encode()
 total=len(head)+len(f'D7 EXPORTED={count} PLANNED={count} STATUS=COMPLETE\r\n'.encode())+len(FOOT)
 for t in targets:
  size=224+t['result_bytes']-(4 if t['kind']!=2 else 0);b64=(size+2)//3*4;lines=(b64+95)//96
  for i in range(t['expected_instances']):total+=len(f'D7 OBJ={t["artifact_base"]+i:08X} N={size} SHA={"0"*64} PRESENT\r\n'.encode())+b64+6*lines
 return {'status':'SELECTION_DRAFT_NOT_A_CARRIER','selection_sha256':digest,'payload':payload,'worst_case_complete_log_bytes':total,'worst_case_qr_pages_at_768':(total+767)//768,'capacity_selected':budget_bytes is not None,
         'capacity_sufficient_for_worst_case':None if budget_bytes is None else budget_bytes>=total,
         'requirements_before_carrier':['Review actual source log and target association.','Explicitly choose total QR budget from measured lengths.','Compile immutable selection; no arbitrary GUID/path input.','Re-enumerate current handles; require expected multiplicity and exact forms length/SHA.','Confirm current producer observations or report changes, never claim ownership.','Run actual EFI/OVMF test and independent review for new carrier.']}
def main():
 p=argparse.ArgumentParser();p.add_argument('log');p.add_argument('--budget-bytes',type=int);p.add_argument('--output',required=True);a=p.parse_args()
 result=prepare(Path(a.log).read_bytes(),a.budget_bytes);dest=Path(a.output);data=json.dumps(result,ensure_ascii=False,indent=2).encode()+b'\n'
 if dest.exists():
  if dest.read_bytes()!=data:raise FileExistsError(dest)
 else:
  dest.parent.mkdir(parents=True,exist_ok=True)
  with dest.open('xb') as f:f.write(data)
 print(json.dumps({k:result[k] for k in ('status','selection_sha256','worst_case_complete_log_bytes','worst_case_qr_pages_at_768','capacity_selected')},indent=2))
if __name__=='__main__':main()
