"""Verify stage-2 fail-closed construction without fabricating a live receipt."""
from pathlib import Path
import hashlib,importlib.util,json,subprocess,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;OUT=HERE/'stage1/build'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec=importlib.util.spec_from_file_location('nv_builder',HERE/'build_nv_test.py');builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
checks=[]
def reject(name,fn):
    try:fn()
    except (ValueError,KeyError,OSError):checks.append(name);return
    raise AssertionError(name+' accepted')
for index,args in enumerate([(None,None,None),('missing.log',None,None),(None,'0'*64,None),(None,None,str(OUT/'build.json'))]):
    reject('missing actual receipt requirement '+str(index),lambda args=args:builder.receipt_binding(*args))
boot=json.loads((OUT/'boot_validation.json').read_text(encoding='utf8'))
for case in boot['cases']:
    log=Path(case['folder'])/'RESTORED-LOG.TXT'
    reject('non-target OVMF QR cannot substitute for stage1 commit '+str(case['spoofed_target_smbios']),lambda log=log:builder.receipt_binding(log,sha(log),OUT/'build.json'))
    reject('explicit receipt digest mismatch rejected '+str(case['spoofed_target_smbios']),lambda log=log:builder.receipt_binding(log,'0'*64,OUT/'build.json'))
cmd=[sys.executable,str(HERE/'build_nv_test.py'),'--stage','2','--create-iso','--expected-driver-sha',builder.PIN]
result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
assert result.returncode==2 and 'Stage 2 requires the actual stage-1 QR log' in result.stderr
assert not (HERE/'stage2').exists(),'Stage 2 must fail before creating any output directory'
checks+=['stage2 CLI refuses absent live receipt before writing files','no stage2 EFI, ISO or synthetic hardware receipt created']
report={'status':'PASS_STAGE2_MISSING_REAL_RECEIPT_FAILS_CLOSED','checks':len(checks),'check_names':checks,
        'stage2_media_created':False,'synthetic_hardware_receipt_created':False,'stage1_manifest_sha256':sha(OUT/'build.json'),
        'efi_sha256':json.loads((OUT/'build.json').read_text(encoding='utf8'))['efi_sha256'],
        'source_sha256':sha(Path(__file__)),'builder_sha256':sha(HERE/'build_nv_test.py'),
        'unproven':'Positive stage2 media binding waits for an actual successful stage1 hardware QR log.'}
(OUT/'stage2_binding_validation.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:report[k] for k in ['status','checks','stage2_media_created']},indent=2))
