"""Freeze locally validated PID1/initramfs only; loader and actual ISO are separate."""
from pathlib import Path
import datetime,gzip,hashlib,json,struct
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir());sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
build=json.loads((HERE/'build/build.json').read_text());modules=json.loads((HERE/'modules.json').read_text())['modules']
for name,digest in build['source_files'].items():assert sha(HERE/name)==digest
assert sha(HERE/'build/commandline.txt')==build['commandline_sha256'];assert sha(HERE/'official/vmlinuz-lts')==build['kernel_sha256']
archive_checks=[]
for variant in build['variants']:
 folder=HERE/'build'/variant['variant'];image=folder/'CAPACITY01.IMG';assert sha(image)==variant['initramfs_sha256'] and sha(folder/'init')==variant['binary_sha256']
 raw=gzip.decompress(image.read_bytes());offset=0;actual=[]
 while True:
  assert raw[offset:offset+6]==b'070701';v=[int(raw[offset+6+i*8:offset+14+i*8],16) for i in range(13)];offset+=110;n=v[11];name=raw[offset:offset+n-1].decode('ascii');assert raw[offset+n-1]==0;offset=(offset+n+3)&~3;data=raw[offset:offset+v[6]];offset=(offset+v[6]+3)&~3
  if name=='TRAILER!!!':break
  assert not name.startswith('/') and '..' not in name.split('/')
  actual.append({'name':name,'mode':oct(v[1]),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest() if data else None,'device':[v[9],v[10]]})
 assert actual==variant['entries'] and len(actual)==15
 assert {a['name'] for a in actual}=={'dev','proc','sys','modules','dev/console','dev/null','init'}|{'modules/'+m['filename'] for m in modules}
 assert all((int(a['mode'],8)&0o170000) in [0o040000,0o020000,0o100000] for a in actual)
 archive_checks.append({'variant':variant['variant'],'status':'PASS','entry_count':len(actual),'module_count':8,'stock_init':False,'shell_or_helpers':False,'symlinks':False,'dynamic_linker':False,'initramfs_sha256':sha(image),'initramfs_bytes':image.stat().st_size})
native=json.loads((HERE/'native_submit_tests/summary.json').read_text());core=json.loads((HERE/'core_transport_tests/summary.json').read_text());vm=json.loads((HERE/'vm_tests_final03/summary.json').read_text())
assert native['status']==core['status']==vm['status']=='PASS';assert native['elf_sha256']==build['variants'][0]['binary_sha256'];assert core['dll_sha256']==sha(HERE/'build/core_test.dll')
assert native['script_sha256']==sha(HERE/'test_native_submit.py') and core['script_sha256']==sha(HERE/'test_core_and_transport.py') and vm['script_sha256']==sha(HERE/'test_linux_vm.py')
for case in vm['cases']:
 r=json.loads((HERE/'vm_tests_final03'/case['case']['id']/'result.json').read_text());variant=next(x for x in build['variants'] if x['variant']==case['case']['variant']);assert r['status']=='PASS' and r['initramfs_sha256']==variant['initramfs_sha256'];assert all(i['unchanged'] and i['sha_before']==i['sha_after'] for i in r['images'])
dmi_paths=[ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162/hardware-native12-preflight-1793692872117/hardware-log.txt',HERE.parent.parent/'native12_hardware_candidate/source/preflight.c']
review={'status':'PAYLOAD_FROZEN_LOCAL_VALIDATION_PASS','utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'hardware_tested':False,'network_or_bmc_used_by_this_agent':False,
 'kernel':{'path':'official/vmlinuz-lts','bytes':(HERE/'official/vmlinuz-lts').stat().st_size,'sha256':build['kernel_sha256']},
 'production':archive_checks[0],'test_only':archive_checks[1],'production_elf_sha256':native['elf_sha256'],'commandline':build['commandline'],'commandline_sha256':build['commandline_sha256'],
 'validation':{'actual_x64_production_submit_cases':native['case_count'],'core_transport_checks':core['check_count'],'single_page_qr_roundtrips':core['qr_count'],'max_tested_log_bytes':core['max_log_bytes'],'real_linux_ovmf_cases':len(vm['cases']),'all_local_images_unchanged':True},
 'scope':'Read-only standard SG_IO capacity diagnostic from custom RAM-only PID1. At most2 RC10; one repeat only for exact validated initial current fixed-format UNIT ATTENTION06/29/00. No third try or other error retry, no explicit TUR/REQUEST SENSE/reset, no block data command or storage-data write. Kernel autonomous scan/error recovery is separate.',
 'dmi_contract':{'board_name':'Pro WS W790E-SAGE SE','bios_version':'1904','normalization':'Strip at most one terminal LF only','before':'PCI/USB/module work','evidence':[{'path':str(p.relative_to(ROOT)),'sha256':sha(p)} for p in dmi_paths]},
 'boot_boundary':'Separate bootstrap/ISO must be independently reviewed and pinned to this kernel/initrd/commandline. Direct fw_cfg QEMU boots are not evidence that the custom El Torito/EFI loader handoff succeeds. Linux RandomSeed must be absent under the loader read-only gate; MOR helper is compiled out by exact config. No RuntimeServices hook.',
 'log':{'first_line':'LINUX-CAPACITY-01 PRODUCTION','maximum_bytes':768,'transport':'One original AITWK-P3-KVM QR page with per-page and total CRC; compact text fallback with LC01_LOG_BEGIN / LC01_LOG_END BYTES/CRC','pending':'RESULT=PENDING + PROBE_PENDING; never complete','final':'PROBE_COMPLETE only after run returns','decoder':'decode_linux_log.py','packets':'A1/A2 retain return,errno,status,masked,msg,host,driver,residual,info,sense_len,guard,data8,declared sense bytes; CSV order documented in decoder','overflow':'Explicit RESULT=LOG_OVERFLOW, never a valid decoded capacity result'},
 'remaining_limits':['No Linux physical SAGE boot or capacity collection by this agent.','Kernel automatic USB enumeration/SCSI scans and internal retry/error recovery may send additional commands/reset and exceed requested2s timeout; userspace count is not physical transaction count.','USB inventory is a bounded current observation, not a guarantee against future hotplug.','Framebuffer may be unsupported; bounded text/CRC fallback remains.','This does not create a full SPI backup, authorize flashing or establish firmware trust-chain acceptance.']}
(HERE/'payload_review.json').write_text(json.dumps(review,indent=2),encoding='utf8')
files=[]
for base in ['source','native_submit_tests','core_transport_tests','vm_tests_final03']:
 for p in (HERE/base).rglob('*'):
  if p.is_file() and (base!='vm_tests_final03' or p.suffix in ['.json','.txt','.log','.png']):files.append(p)
for name in ['prepare_modules.py','build_initramfs.py','make_design_review.py','test_linux_vm.py','test_native_submit.py','test_core_and_transport.py','decode_linux_log.py','freeze_payload.py','modules.json','source_reuse.json','design_review.json','review/design_initial.json','payload_review.json','build/build.json','build/commandline.txt','build/core_test.dll','build/production/init','build/production/CAPACITY01.IMG','build/lab_selector_only/init','build/lab_selector_only/CAPACITY01.IMG','official/acquisition.json','official/config-6.12.114-0-lts','official/vmlinuz-lts','kernel_source/provenance.json','review/reference/System.map-6.12.114-0-lts']:
 files.append(HERE/name)
files += [HERE/'modules'/m['filename'] for m in modules]
files += [p for p in (HERE/'kernel_source').rglob('*') if p.is_file()]
manifest={'status':'FROZEN_PAYLOAD_ONLY','utc':review['utc'],'production_initramfs_sha256':archive_checks[0]['initramfs_sha256'],'artifact_count':len(set(files)),'files':[{'path':p.relative_to(HERE).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(set(files))],'excluded_scope':'Separate mutable loader directory/ISO is owned by another agent. Historical failed development VMs remain on disk; final verification binds vm_tests_final03 only. VM backing images/variable stores are not release payloads; their before/after hashes are recorded in each final result.'}
(HERE/'payload_manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf8')
print(json.dumps({'status':review['status'],'payload_manifest_sha256':sha(HERE/'payload_manifest.json'),'artifact_count':manifest['artifact_count'],'production':archive_checks[0],'validation':review['validation']},indent=2))
