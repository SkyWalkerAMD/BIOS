"""Recover exact D7 forms structures; diagnostics are never runtime authority."""
from pathlib import Path
import argparse,hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'analysis/aitweaker_lock/probe_p3_kvm'))
from decode_captures import assemble,read_image
from transport import parse
from decode_packet import CPU,NVME,SOCKET
from prepare_selection import canonical
def write_new(path,data):
 if path.exists():
  if path.read_bytes()!=data:raise FileExistsError(path)
 else:
  path.parent.mkdir(exist_ok=True,parents=True);path.write_bytes(data)
def decode_log(data,selection):
 payload=selection['payload'];digest=hashlib.sha256(canonical(payload)).hexdigest()
 if digest!=selection['selection_sha256'] or payload['qr_budget_bytes']!=15360:raise ValueError('Selection digest/budget')
 bases={g:(HERE.parent/'foreign_hii05/blobs'/f'{name}_0.forms.bin').read_bytes() for g,name in ((CPU,'GetCpuInfo'),(NVME,'NvmeDynamicSetup'),(SOCKET,'SocketSetup'))}
 result=parse(data,payload['targets'],bytes.fromhex(payload['source_log_sha256']),bytes.fromhex(digest),bases,15360)
 profiles=json.loads((HERE.parent/'diagnostic_hii06/build/profiles.json').read_text());by_guid={p['guid'].lower():p for p in profiles}
 for target in payload['targets']:
  for i in range(target['expected_instances']):
   ob=result['observations'].get(target['artifact_base']+i)
   if not ob or ob['status'] not in ('ORIGINAL_CODE_MATCH','UNKNOWN_OBSERVED'):continue
   if not int(ob['hii'],16) or not int(ob['producer'],16) or not int(ob['base'],16):raise ValueError('Matching observation without current addresses')
   if target['kind']==2:
    modules=[m for m in payload['source_module_observations'] if m['reported_ffs_guid']=='NONFV']
    if not modules or len({m['raw_sha256'] for m in modules})!=1 or ob['raw_sha']!=modules[0]['raw_sha256'] or ob['normalized_sha']!='-':raise ValueError('Unknown producer observation changed')
   else:
    g='ee0bff80-2b33-4005-8ef1-3f9b23c25136' if target['kind']==1 else target['package_list_guid'];profile=by_guid[g]
    if ob['normalized_sha']!=profile['text_sha256'] or ob['raw_sha']=='-':raise ValueError('Original code observation contradicts fixed profile')
 result['selection_sha256']=digest;result['source_log_sha256']=payload['source_log_sha256'];return result
def main():
 p=argparse.ArgumentParser();p.add_argument('inputs',nargs='+');p.add_argument('--text-log',action='store_true');p.add_argument('--selection',default=str(HERE/'selection_hardware02.json'));p.add_argument('--output',required=True);a=p.parse_args()
 if a.text_log:
  if len(a.inputs)!=1:raise ValueError('One text log required')
  data=Path(a.inputs[0]).read_bytes()
 else:
  paths=[]
  for name in a.inputs:
   path=Path(name);paths.extend(sorted(path.glob('*.png')) if path.is_dir() else [path])
  data,_=assemble([read_image(path) for path in paths])
 selection=json.loads(Path(a.selection).read_text());decoded=decode_log(data,selection);dest=Path(a.output);out={**decoded,'objects':{}}
 for artifact,item in decoded['objects'].items():
  meta=item['metadata'];name=f"object-{artifact:02}-{meta['current_hii']}-{meta['package_index']:04}.forms.bin";path=dest.parent/name;write_new(path,item['forms']);out['objects'][artifact]={**meta,'file':str(path.resolve())}
 write_new(dest,json.dumps(out,ensure_ascii=False,indent=2).encode()+b'\n');write_new(dest.with_suffix('.log.txt'),data)
 print(json.dumps({'objects':len(out['objects']),'omitted':out['omitted'],'refused':out['refused'],'complete_transport':out['complete'],'authorization':False,'output':str(dest)},indent=2))
if __name__=='__main__':main()
