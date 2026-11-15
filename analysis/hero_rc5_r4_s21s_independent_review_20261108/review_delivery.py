"""Read every delivery member and its manifest; no core tests or hardware."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,io,json,re,stat,sys,zipfile
if not __debug__:raise RuntimeError('Assertions required')
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
NAME='HERO-3107-IPMI-RC5-C03-20261108';BUILD='RC5-IPMI-ONLY-R4-S21S-CANDIDATE03'
ZIP=ROOT/('analysis/hero_ipmi_rc5_s21s_20261108/delivery/'+NAME+'.zip')
PINS={'01-IPMI-RC5-C03/MZ790H.CAP':'7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624',
 '90-ASUS-3107-RECOVERY/MZ790H.CAP':'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a',
 '02-LOG-CAPTURE/HERO-P6-RC4-READONLY-LOG.iso':'8c4c3cbd0df0d5ca56042aa643b9bc4d090358de764b5d7ac10fe18b17617c94',
 '02-LOG-CAPTURE/USB/EFI/BOOT/BOOTX64.EFI':'7d758a6d16af86e0b7bf8a82d6dd69aa36ef0250c2699982299650f3da447fc3',
 '03-VERIFICATION/final-review.json':'a79ff878194b87f5272517b3c3262f4d8a41efa968a6ad4dcaada1bd5f932e4c',
 '03-VERIFICATION/s21s-hardware-verification.json':'7133485ca073e689322ca48b2af887e4fc0ed7b7f8353212e224dcf0f1f1c591'}
def sha(b):return hashlib.sha256(b).hexdigest()
def text(b):return b.decode('utf-8-sig')
def safe(p):
 assert '\\' not in p and ':' not in p and not p.startswith('/')
 parts=PurePosixPath(p).parts;assert parts and not any(x in ('.','..') for x in parts)
 return p
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--sha256',required=True);parser.add_argument('--bytes',required=True,type=int);parser.add_argument('--archive',type=Path,default=ZIP)
 args=parser.parse_args();archive=args.archive.resolve();assert archive.parent==ZIP.parent
 raw=archive.read_bytes();assert len(raw)==args.bytes and sha(raw)==args.sha256
 files={}
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  label=z.infolist()[0].filename.split('/')[0];assert label in (NAME,'HERO-3107-IPMI-RC5-C03-FLASHBACK-20261108')
  seen=set()
  for i in z.infolist():
   assert not i.is_dir() and i.filename.startswith(label+'/') and not i.flag_bits&1
   assert not stat.S_ISLNK(i.external_attr>>16)
   path=safe(i.filename[len(label)+1:]);assert path.casefold() not in seen;seen.add(path.casefold())
   data=z.read(i);assert len(data)==i.file_size;files[path]=data
 assert set(p for p in files if p.lower().endswith('.cap'))==set(k for k in PINS if k.lower().endswith('.cap'))
 assert set(p for p in files if p.lower().endswith(('.iso','.efi')))==set(k for k in PINS if k.lower().endswith(('.iso','.efi')))
 assert not any(re.search('RAMCHECK|CANDIDATE0[12]|I3[A-Z]?NET|I5[A-Z]?NET',p,re.I) for p in files)
 for p,h in PINS.items():assert sha(files[p])==h
 for p in PINS:
  if p.endswith('.CAP'):assert len(files[p])==33558528
 manifest=json.loads(files['manifest.json']);assert manifest['package']==label and manifest['build_id']==BUILD
 assert manifest['status']=='FIELD_VALIDATION_CANDIDATE'
 assert manifest['inventory_publisher_included'] is False and manifest['runtime_test_loader_included'] is False
 assert manifest['cap_sha256']==PINS['01-IPMI-RC5-C03/MZ790H.CAP']
 assert manifest['official_recovery_sha256']==PINS['90-ASUS-3107-RECOVERY/MZ790H.CAP']
 listed=set()
 for row in manifest['files']:
  p=safe(row['path']);assert p not in listed;listed.add(p)
  assert len(files[p])==row['bytes'] and sha(files[p])==row['sha256']
 assert listed==set(files)-{'manifest.json','SHA256SUMS.txt'}
 sums={}
 for line in text(files['SHA256SUMS.txt']).splitlines():
  h,p=line.split('  ',1);safe(p);assert p not in sums and re.fullmatch('[0-9a-f]{64}',h)
  assert sha(files[p])==h;sums[p]=h
 assert set(sums)==set(files)-{'SHA256SUMS.txt'}
 mapping=json.loads(files['03-VERIFICATION/source-map.json']);mapped={};by_source={}
 for row in mapping:
  p=safe(row['package_path']);src=safe(row['workspace_source']);assert p not in mapped
  origin=(ROOT/src).resolve();assert origin.is_relative_to(ROOT)
  assert len(files[p])==row['bytes'] and sha(files[p])==row['sha256'] and origin.read_bytes()==files[p]
  mapped[p]=row;by_source[src]=p
 summary=json.loads(files['03-VERIFICATION/final-review.json']);assert summary['passed'] and summary['field_candidate_packaging_allowed']
 linked=[];workspace_only=[]
 for name,row in summary['reports'].items():
  src=row['path'];p=by_source.get(src)
  if p:
   assert sha(files[p])==row['sha256'] and len(files[p])==row['bytes'];linked.append(name)
  else:workspace_only.append(src)
 hw=json.loads(files['03-VERIFICATION/s21s-hardware-verification.json'])
 for row in hw['captures']+hw['photos']:
  p=by_source[row['path'].replace('\\','/')];assert sha(files[p])==row['sha256'] and len(files[p])==row['bytes']
 for stem in ('hero71-p6s21s-loaded','hero71-p6s21s-after-return','hero71-p6s21s-repeat-return'):
  p='03-VERIFICATION/qr/'+stem+'/';m=json.loads(files[p+'manifest.json']);b=files['03-VERIFICATION/logs/'+stem+'.TXT']
  assert len(b)==m['bytes'] and sha(b)==m['sha256']
  for row in m['screens']:assert sha(files[p+f"{row['page']:03d}.png"])==row['sha256']
 manual=text(files['现场刷写与验证手册.txt']);note=text(files['先读我.txt'])
 assert not re.search(r'\{[A-Z0-9_]+\}',manual) and BUILD in manual
 assert all(PINS[p] in manual for p in PINS if p.endswith('.CAP'))
 s5=manual.split('五、首次启动验收',1)[1].split('六、配置写入',1)[0]
 assert s5.index('先保存BMC网页传感器基线')<s5.index('正常启动原操作系统')<s5.index('间隔30～60秒')
 assert '不能因这时仍只有原先项目就判定初始化失败' in s5
 assert all(s in manual for s in ('首次进入 BIOS 的 SetupEnter 定时路径尚未获得实机验证','当前已通过的实机测试使用内存加载驱动','原生编辑→F10→下一次启动→BMC读回的完整实机验证尚未完成','本轮尚未实刷候选03，也尚未验证从候选03恢复官方','本包不附带RAMCHECK加载器'))
 assert '最终CAP尚未实刷' in note
 result=dict(passed=not workspace_only,package_integrity_passed=True,all_member_crc_and_hashes_verified=True,
  zip=dict(path=archive.relative_to(ROOT).as_posix(),bytes=len(raw),sha256=sha(raw)),member_count=len(files),manifest_hashed_members=len(listed),sha256sums_members=len(sums),source_mappings_verified=len(mapped),
  exactly_two_caps_in_separate_directories=True,only_fixed_readonly_collector_iso_and_efi=True,
  failed_candidates_or_ram_loaders_included=False,manual_placeholders_replaced=True,r4_final_sensor_check_after_os_launch=True,
  exact_candidate_and_recovery=PINS,final_review_reports_mapped=linked,final_review_reports_workspace_only=workspace_only,
  preserved_all_eight_s21s_photos_and_three_logs=True,manual_limits_preserved=True,
  scope='Delivery contents only; no firmware tests repeated and no hardware accessed.')
 name='delivery-review.json' if result['passed'] else 'delivery-review-preliminary.json'
 p=OUT/name;p.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf8')
 print(json.dumps(dict(passed=result['passed'],zip_sha256=sha(raw),members=len(files),source_mappings=len(mapped),workspace_only=workspace_only,report=name,report_sha256=sha(p.read_bytes()))))
if __name__=='__main__':main()
