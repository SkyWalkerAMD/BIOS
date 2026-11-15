"""Independent exact RC5-R4/S21 byte and negative-policy review. Offline only."""
from pathlib import Path
import contextlib,copy,hashlib,importlib.util,io,json,lzma,struct,subprocess,sys,unittest
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[1]
SOURCE=ROOT/'analysis/hero_ipmi_rc5_20261108'
ORIGIN=SOURCE/'RC5-IPMI-ONLY-R4-S21-CANDIDATE01'
CAP=ORIGIN/'HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21-CANDIDATE01-UNSIGNED.CAP'
PIN='0f755eb739d83e40b289c2835d44e29f97f6c106a6820e57c4397ba648a4beaa'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path)
 obj=importlib.util.module_from_spec(spec);sys.modules[name]=obj;spec.loader.exec_module(obj);return obj
a=load('old_independent_helpers',ROOT/'analysis/hero_rc5_independent_review_20261108/audit_rc5.py')
EXPECTED={
 a.R2:('3b3665040f28e374b0056fd98a7b1b283f6baaeb77067f34e3d701564fb04ed3','a3036261c18bd66b158844a6818cf828b54af002dbb9ecf45d8dbc97a5317b2f',ROOT/'analysis/hero_sensor_r4_20261108/HeroIpmiCoreR4.ffs'),
 a.P6:('c5745d255cdda51406c2bb846d3d1370efbefce87b244fa944576b8467b827a7','6a5e2c86f9e49ceefa47d8765cf45c585805f7ac164f07be07df6505100d8ffb',ROOT/'analysis/hero_p6_settings21_20261108/HeroIpmiNativeP6.ffs')}
def save(name,obj):(OUT/name).write_text(json.dumps(obj,indent=2)+'\n',encoding='utf8')
def repack(parsed,order=None,replacements=None):
 replacements=replacements or {};out=bytearray(parsed['header'])
 for g in order or parsed['order']:
  out.extend(b'\xff'*(a.aligned(len(out),8)-len(out)));out.extend(replacements.get(g,parsed['files'][g]['data']))
 size=parsed['used_bytes']+parsed['free_bytes']
 assert len(out)<=size;out.extend(b'\xff'*(size-len(out)));return bytes(out)
def header(blob):
 x=bytearray(blob);x[20:23]=len(x).to_bytes(3,'little');x[16]=0;x[16]=-(sum(x[:16])+sum(x[18:23]))&255;return bytes(x)
def wrapper_with_plain(current,plain,folder):
 folder.mkdir(exist_ok=True)
 (folder/'plain.bin').write_bytes(plain)
 subprocess.run([str(ROOT/'analysis/hero_ipmi_p5/host-lzma/encode.exe'),str(folder/'plain.bin'),str(folder/'encoded.lzma')],check=True,capture_output=True)
 z=(folder/'encoded.lzma').read_bytes();assert lzma.decompress(z,format=lzma.FORMAT_ALONE)==plain
 assert z[:5]==current['compressed'][:5]
 old=current['outer']['files'][a.WRAPPER]['data'];s=current['wrapper'][0]
 section=bytearray(s['data'][:s['head']+20]+z)
 assert s['head']==4;section[:3]=len(section).to_bytes(3,'little')
 return header(old[:24]+section)
def with_outer(current,outer):return current['cap'][:a.BASE]+outer+current['cap'][a.BASE+a.LENGTH:]

def main():
 names=('build_candidate.py','verify_candidate.py','test_builder_guards.py')
 sources={n:sha((SOURCE/n).read_bytes()) for n in names}
 snapshot=OUT/'reviewed-source';snapshot.mkdir(exist_ok=True)
 for n in names:
  (snapshot/n).write_bytes((SOURCE/n).read_bytes())
  # The relocated author suite starts these copies only with -O; both reject
  # optimized execution before resolving any ROOT or importing build helpers.
  (OUT/n).write_bytes((SOURCE/n).read_bytes())
 source_report=json.loads((ORIGIN/'build-report.json').read_text(encoding='utf8'))
 source_manifest=json.loads((ORIGIN/'integration-manifest.json').read_text(encoding='utf8'))
 assert sha(CAP.read_bytes())==PIN
 old,new=a.image(a.BASELINE),a.image(CAP)
 official=a.OFFICIAL.read_bytes()
 assert sha(old['cap'])==a.PINNED['baseline'] and sha(official)==a.PINNED['official']
 for ref in (old['cap'],official):
  assert new['cap'][:a.BASE]==ref[:a.BASE] and new['cap'][a.BASE+a.LENGTH:]==ref[a.BASE+a.LENGTH:]
 assert new['cap'][:4096]==official[:4096]
 unchanged=[];changes={}
 for layer,wanted in [('outer',{a.WRAPPER}),('inner',set(EXPECTED))]:
  assert old[layer]['order']==new[layer]['order'] and old[layer]['header']==new[layer]['header']
  found=[]
  for guid,entry in old[layer]['files'].items():
   other=new[layer]['files'][guid]['data']
   if entry['data']!=other:found.append(guid)
   else:unchanged.append(dict(layer=layer,guid=guid,bytes=len(other),sha256=sha(other)))
  assert set(found)==wanted;changes[layer]=found
 before=old['outer']['files'][a.WRAPPER]['data'];after=new['outer']['files'][a.WRAPPER]['data']
 for start,end in ((0,16),(17,20),(23,24)):assert before[start:end]==after[start:end]
 assert len(old['plain'])==len(new['plain']) and old['compressed'][:5]==new['compressed'][:5]
 assert old['wrapper'][0]['data'][4:24]==new['wrapper'][0]['data'][4:24]
 assert [(s['type'],s['offset'],s['head'],len(s['body'])) for s in old['parts']]==[(s['type'],s['offset'],s['head'],len(s['body'])) for s in new['parts']]
 s=old['parts'][1];start=s['offset']+s['head'];end=start+len(s['body'])
 assert old['plain'][:start]==new['plain'][:start] and old['plain'][end:]==new['plain'][end:]
 import pefile
 payloads=[]
 for guid,(ffs_sha,pe_sha,path) in EXPECTED.items():
  blob=new['inner']['files'][guid]['data'];ss=a.sections(blob[24:]);pebytes=ss[1]['body']
  assert blob==path.read_bytes() and sha(blob)==ffs_sha and sha(pebytes)==pe_sha
  assert [s['type'] for s in ss]==[0x13,0x10,0x15]
  assert ss[0]['body']==a.sections(old['inner']['files'][guid]['data'][24:])[0]['body']
  pe=pefile.PE(data=pebytes)
  assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Magic==0x20b and pe.OPTIONAL_HEADER.Subsystem==11
  assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.verify_checksum() and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
  good=a.run_native_validator(blob[24:]);bad=a.run_native_validator(blob[24:]+b'\0\0')
  assert good and not bad
  payloads.append(dict(guid=guid,ffs_sha256=ffs_sha,pe_sha256=pe_sha,ffs_bytes=len(blob),pe_bytes=len(pebytes),depex_unchanged=True,strict_sections=True,target_DxeCore_accepts=True,target_DxeCore_rejects_two_zero_tail=True,ui=ss[2]['body'].decode('utf16').rstrip('\0')))
 save('unchanged-ffs.json',unchanged)
 result=dict(passed=True,candidate_sha256=PIN,candidate_bytes=len(new['cap']),baseline_sha256=sha(old['cap']),official_sha256=sha(official),changes=changes,unchanged_ffs_count=len(unchanged),no_new_or_removed_guids=True,original_order=True,outside_dxe_exact=True,capsule_header_exact=True,wrapper_metadata_and_non_fv_exact=True,fv_checksums_alignment_erased_fill=True,inner_free_bytes=new['inner']['free_bytes'],outer_free_bytes=new['outer']['free_bytes'],payloads=payloads,hardware_flash_performed=False,scope='Independent parser + pinned actual target DxeCore local instruction validation. Does not prove native post-flash lifecycle.')
 save('independent-byte-audit.json',result)

 # Root checker is exercised only against copies inside this new review tree.
 builder=load('build_candidate',SOURCE/'build_candidate.py');builder.HERE=OUT
 verifier=load('verify_candidate',SOURCE/'verify_candidate.py')
 suite=load('root_guard_tests',SOURCE/'test_builder_guards.py')
 log=io.StringIO();run=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(suite.GuardTests))
 (OUT/'root-guards.txt').write_text(log.getvalue(),encoding='utf8');assert run.wasSuccessful()
 cases=[]
 def candidate_copy(label,cap,manifest=None):
  folder=OUT/label;folder.mkdir(exist_ok=False)
  m=copy.deepcopy(source_manifest if manifest is None else manifest);m['build_id']=label
  p=folder/('HERO-3107-IPMI-'+label+'-UNSIGNED.CAP');p.write_bytes(cap)
  mf=folder/'integration-manifest.json';mf.write_text(json.dumps(m,indent=2)+'\n',encoding='utf8')
  report=copy.deepcopy(source_report);report.update(build_id=label,candidate=str(p.relative_to(ROOT)),candidate_sha256=sha(cap),manifest_sha256=sha(mf.read_bytes()),candidate_bytes=len(cap))
  (folder/'build-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8');return folder
 def verdict(label,cap,expected=False,manifest=None):
  folder=candidate_copy(label,cap,manifest)
  res=a.capture_verify(verifier,folder)
  assert res['accepted']==expected,(label,res)
  cases.append(dict(case=label,passed=True,accepted=res['accepted'],exception=res.get('exception'),detail=res.get('detail')))
 verdict('POSITIVE-FROZEN-R4-S21',new['cap'],True)
 verdict('NEGATIVE-BASELINE-UNCHANGED',old['cap'])
 b=bytearray(new['cap']);b[0x1200]^=1;verdict('NEGATIVE-OUTSIDE-DXE',bytes(b))
 order=list(new['outer']['order']);order[2],order[3]=order[3],order[2]
 verdict('NEGATIVE-OUTER-ORDER',with_outer(new,repack(new['outer'],order)))
 f=bytearray(new['outer']['files'][a.WRAPPER]['data']);f[18]=7 if f[18]!=7 else 0x0b
 verdict('NEGATIVE-WRAPPER-TYPE',with_outer(new,repack(new['outer'],replacements={a.WRAPPER:header(f)})))
 # Recompress a candidate with an unrelated existing inner FFS payload changed.
 target=next(g for g in new['inner']['order'] if g not in EXPECTED and new['inner']['files'][g]['bytes']>40)
 f=bytearray(new['inner']['files'][target]['data']);f[-1]^=1
 inner=repack(new['inner'],replacements={target:header(f)})
 plain=new['plain'][:start]+inner+new['plain'][end:]
 wrapper=wrapper_with_plain(new,plain,OUT/'negative-unrelated-compression')
 verdict('NEGATIVE-UNRELATED-INNER',with_outer(new,repack(new['outer'],replacements={a.WRAPPER:wrapper})))
 # A manifest with self-approved bytes cannot override independent release pins.
 m=copy.deepcopy(source_manifest);m['modules'][0]['sha256']='0'*64
 verdict('NEGATIVE-SELF-APPROVED-MANIFEST',new['cap'],manifest=m)
 for index,field,value in [(0,'role','native_ipmi'),(1,'role','sensors_dashboard'),(0,'guid',a.P6),(1,'guid',a.R2),(1,'role','inventory'),(1,'pe_sha256','f'*64),(1,'path','../not-local.ffs')]:
  items=copy.deepcopy(source_manifest['modules']);items[index][field]=value
  try:verifier.approved_modules(items)
  except Exception:pass
  else:raise AssertionError((index,field,value))
  cases.append(dict(case=f'manifest reject {index} {field} {value}',passed=True,accepted=False))
 for filename in ('build_candidate.py','verify_candidate.py'):
  p=subprocess.run([sys.executable,'-I','-S','-B','-O',str(SOURCE/filename),'--help'],capture_output=True,text=True)
  assert p.returncode!=0 and 'Optimized Python' in p.stderr
  cases.append(dict(case=filename+' -O rejected',passed=True,accepted=False))
 after={n:sha((SOURCE/n).read_bytes()) for n in names}
 assert sources==after
 save('verification-regressions.json',dict(passed=True,cases=len(cases),root_guards=run.testsRun,results=cases,source_sha256=sources,source_unchanged=True,no_parent_files_modified=True,no_hardware_access=True))
 print(json.dumps(dict(passed=True,candidate_sha256=PIN,independent_cases=len(cases),root_guard_cases=run.testsRun,unchanged_ffs=len(unchanged),payloads=payloads),indent=2))

if __name__=='__main__':main()
