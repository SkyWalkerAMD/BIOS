"""Build a local, isolated-console ACE1904 NVRAM test; never access a BMC.

Stage 2 is refused without an explicit, hash-pinned real stage-1 QR log and
the matching stage-1 build manifest. No example credential/hash is substituted.
"""
from pathlib import Path
import argparse, hashlib, io, json, os, re, subprocess, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'tools/zig-x86_64-windows-0.14.1/zig.exe').is_file())
CASE = HERE.parent/'lock_1904_candidate05'
DRIVER = CASE/'driver'
PIN = '71b05ebe21fd0b4de496fc9684f57e4acc79431e38a403dec9017501605eca98'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

def receipt_binding(path, expected_log_sha, manifest_path):
    if not path or not expected_log_sha or not manifest_path:
        raise ValueError('Stage 2 requires the actual stage-1 QR log, its explicit SHA256 and stage-1 manifest; none is available by default')
    path, manifest_path = Path(path), Path(manifest_path)
    if sha(path) != expected_log_sha:
        raise ValueError('Stage-1 log SHA256 mismatch')
    manifest = json.loads(manifest_path.read_text(encoding='utf8'))
    if manifest['stage'] != 1 or manifest['production_driver_sha256'] != PIN:
        raise ValueError('Stage-1 manifest identity mismatch')
    for source in ['nv_guard.c','nv_guard.h','nv_maintenance.c','build_nv_test.py']:
        if sha(HERE/source) != manifest['local_sources'][source]:
            raise ValueError('Stage-1 implementation changed before stage 2: '+source)
    for name,digest in manifest['all_production_object_hashes'].items():
        if sha(DRIVER/'build'/name) != digest:
            raise ValueError('Frozen production object changed before stage 2: '+name)
    if sha(manifest['efi_path']) != manifest['efi_sha256']:
        raise ValueError('Stage-1 EFI changed')
    log = path.read_text(encoding='ascii').replace('\r\n','\n')
    def one(key):
        found = re.findall(r'^'+re.escape(key)+r'=(.+)$', log, re.M)
        if len(found) != 1: raise ValueError('Missing/duplicate receipt field: '+key)
        return found[0]
    expected = {
        'DriverSHA256': PIN, 'SourceBundleSHA256': manifest['source_bundle_sha256'],
        'Phase1Receipt':'COMMITTED_EXACT_READBACK', 'Stage':'0x0000000000000001',
        'CredentialAttributes':'0x0000000000000003', 'CredentialBytes':'0x0000000000000080',
        'CredentialGeneration':'0x0000000000000001', 'AcceptedWrites':'0x0000000000000001',
        'LastNativeSetStatus':'0x0000000000000000', 'LastNativeGetStatus':'0x0000000000000000',
        'OwnershipKnown':'0x0000000000000001', 'Fault':'0x0000000000000000',
        'Failures':'0x0000000000000000', 'CoreActive':'0x0000000000000000',
        'CoreUnlocked':'0x0000000000000000',
    }
    if 'ACE1904-CANDIDATE05-NV-STAGE1\n' not in log:
        raise ValueError('Wrong stage-1 log identity')
    for key,value in expected.items():
        if one(key) != value: raise ValueError('Stage-1 receipt requirement failed: '+key)
    digest = one('CredentialSHA256')
    if not re.fullmatch('[0-9a-f]{64}',digest) or digest == '0'*64:
        raise ValueError('Invalid stage-1 record SHA256')
    return {'log_path':str(path.resolve()), 'log_sha256':sha(path),
            'manifest_path':str(manifest_path.resolve()), 'manifest_sha256':sha(manifest_path),
            'stage1_efi_sha256':manifest['efi_sha256'], 'record_sha256':digest,
            'origin':'Operator-supplied hardware QR log; parser binds content, not physical-origin authenticity.'}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', choices=[1,2], type=int, required=True)
    p.add_argument('--expected-driver-sha', required=True)
    p.add_argument('--receipt-log');p.add_argument('--expected-receipt-sha');p.add_argument('--stage1-manifest')
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--prepare-only', action='store_true');mode.add_argument('--create-iso', action='store_true')
    args=p.parse_args()
    if args.expected_driver_sha != PIN: p.error('Frozen production05 identity mismatch')
    try:
        receipt = receipt_binding(args.receipt_log,args.expected_receipt_sha,args.stage1_manifest) if args.stage==2 else None
        if args.stage==1 and any([args.receipt_log,args.expected_receipt_sha,args.stage1_manifest]):
            raise ValueError('Stage 1 must not adopt an existing record')
    except (ValueError,KeyError,OSError) as e: p.error(str(e))
    out=HERE/('stage'+str(args.stage))/'build';src=out/'source';src.mkdir(parents=True,exist_ok=True)
    for name in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/name))
    import pefile,pycdlib
    from pyfatfs.PyFat import PyFat
    from pyfatfs.PyFatFS import PyFatFS
    def checksum(path):
        pe=pefile.PE(str(path));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();path.write_bytes(pe.write());pe.close()
    build_id='ACE1904-CANDIDATE05-NV-STAGE'+str(args.stage)
    prod_path=DRIVER/'build/build.json';prod=json.loads(prod_path.read_text(encoding='utf8'))
    production_efi=DRIVER/'build/AiTweakerLock1904.efi'
    assert sha(production_efi)==prod['efi_sha256']==PIN and prod['revision']=='ACE1904_CANDIDATE05'
    assert all(sha(CASE/f)==h for f,h in prod['sources'].items())
    assert all(sha(ROOT/f)==h for f,h in prod['external_sources'].items())
    zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
    env=os.environ.copy();env.update(ZIG_GLOBAL_CACHE_DIR=str(out/'.zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'.zig-local'),PYTHONDONTWRITEBYTECODE='1')
    commands=[]
    def run(cmd):
        commands.append(cmd);subprocess.run(cmd,check=True,cwd=HERE,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    relink=out/'PRODUCTION-RELINK-CHECK.EFI'
    cmd=[('/out:'+str(relink)) if a.startswith('/out:') else ('/map:'+str(out/'production-relink.map')) if a.startswith('/map:') else a for a in prod['commands'][-1]]
    assert cmd[:2]==[str(zig),'lld-link']
    all_objects=[Path(a) for a in cmd if a.lower().endswith('.obj')]
    assert all(o.resolve().is_relative_to((DRIVER/'build').resolve()) for o in all_objects)
    obj_hash={o.name:sha(o) for o in all_objects}
    run(cmd);checksum(relink);assert sha(relink)==PIN
    entry=(DRIVER/'entry.c').read_text(encoding='utf8')
    names=['loaded_guid','browser_guid','smbios3_guid','smbios_guid','tse_guid','setup_guid']
    guids='\n'.join(line for line in entry.splitlines() if line.startswith(tuple('static GUID '+n for n in names)))
    assert len(guids.splitlines())==6
    functions=entry[entry.index('static int equal_ascii('):entry.index('static void EA discover(')]
    (src/'target_detect.h').write_text(guids+'\n'+functions,encoding='utf8')
    p3=ROOT/'analysis/aitweaker_lock/probe_p3_kvm/source'
    external={str(f.relative_to(ROOT)):sha(f) for f in sorted(p3.rglob('*')) if f.is_file() and f.suffix in {'.c','.h'}}
    local={f.name:sha(f) for f in sorted(HERE.iterdir()) if f.is_file() and f.suffix in {'.c','.h','.py'}}
    bundle=hashlib.sha256(json.dumps({'local':local,'production':prod['sources'],'external':external},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    expected=bytes.fromhex(receipt['record_sha256']) if receipt else bytes(32)
    identity='#define NV_BUILD_ID "'+build_id+'"\n#define NV_DRIVER_SHA "'+PIN+'"\n#define NV_STAGE '+str(args.stage)+'u\n'
    identity+='#define NV_SOURCE_BUNDLE_SHA "'+bundle+'"\n#define NV_RECEIPT_LOG_SHA "'+(receipt['log_sha256'] if receipt else 'NOT_APPLICABLE_STAGE1')+'"\n'
    identity+='static const uint8_t NV_EXPECTED_RECORD[32]={'+','.join(str(b) for b in expected)+'};\n'
    (src/'build_identity.h').write_text(identity,encoding='ascii')
    kvm=(p3/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG',build_id)
    kvm=kvm.replace('COMPLETE INVENTORY - DIAGNOSTIC ONLY','NVRAM MAINTENANCE - REVIEW METADATA').replace('PARTIAL INVENTORY - DIAGNOSTIC ONLY','NVRAM MAINTENANCE - CHECKS FAILED')
    (src/'kvm.c').write_text(kvm,encoding='utf8')
    objs=[]
    for f in [HERE/'nv_guard.c',HERE/'nv_maintenance.c',src/'kvm.c',p3/'vendor/qrcodegen.c']:
        obj=out/(f.stem+'.obj');objs.append(str(obj))
        run([str(zig),'clang','-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(zig.parent/'lib/include'),
             '-I',str(DRIVER),'-I',str(HERE),'-I',str(src),'-I',str(p3),'-I',str(p3/'compat'),
             '-std=c11','-O2','-Wall','-Wextra','-Werror','-DNDEBUG','-ffreestanding','-fno-builtin',
             '-fno-stack-protector','-mno-red-zone','-fshort-wchar','-c',str(f),'-o',str(obj)])
    linked=['password_core.obj','password_crypto.obj','services.obj','ui.obj','cpu_entropy.obj','probe_core.obj','save_feedback.obj']
    assert all(n in obj_hash for n in linked)
    objs += [str(DRIVER/'build'/n) for n in linked]
    efi=out/'BOOTX64.EFI'
    run([str(zig),'lld-link','/subsystem:efi_application','/entry:efi_main','/nodefaultlib','/machine:x64',
         '/dynamicbase','/fixed:no','/nxcompat','/timestamp:0','/map:'+str(out/'nv_test.map'),'/out:'+str(efi)]+objs)
    checksum(efi);pe=pefile.PE(str(efi))
    assert pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum() and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size;pe.close()
    iso_path=None
    if args.create_iso:
        boot=out/'eltorito.img';boot.write_bytes(b'');fat=PyFat();fat.mkfs(str(boot),fat_type=16,size=16*1024*1024,label='ACE_NV_TEST');fat.close()
        with PyFatFS(str(boot),utc=True) as fs:
            fs.makedirs('/EFI/BOOT',recreate=True);fs.writebytes('/EFI/BOOT/BOOTX64.EFI',efi.read_bytes())
            assert fs.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()
        iso_path=out/(build_id+'.iso');iso=pycdlib.PyCdlib();iso.new(interchange_level=3,vol_ident='ACE_NV_STAGE'+str(args.stage),joliet=3)
        iso.add_file(str(boot),iso_path='/EFIBOOT.IMG;1',joliet_path='/EFIBOOT.IMG')
        iso.add_eltorito('/EFIBOOT.IMG;1',bootcatfile='/BOOT.CAT;1',boot_load_size=boot.stat().st_size//512,platform_id=0xef,efi=True,media_name='noemul',bootable=True)
        iso.write(str(iso_path));iso.close();iso=pycdlib.PyCdlib();iso.open(str(iso_path));buffer=io.BytesIO();iso.get_file_from_iso_fp(buffer,iso_path='/EFIBOOT.IMG;1');iso.close()
        assert buffer.getvalue()==boot.read_bytes()
    assert sha(production_efi)==PIN and all(sha(o)==obj_hash[o.name] for o in all_objects)
    assert all(sha(HERE/f)==h for f,h in local.items()) and all(sha(ROOT/f)==h for f,h in external.items())
    result={'status':'BUILT_LOCAL_NVRAM_TEST_NOT_HARDWARE_TESTED','build_id':build_id,'stage':args.stage,
        'production_driver_sha256':PIN,'production_manifest_sha256':sha(prod_path),'production_object_relink_exact_match':True,
        'production_sources':prod['sources'],'production_external_sources':prod['external_sources'],
        'all_production_object_hashes':obj_hash,'linked_objects':{n:obj_hash[n] for n in linked},
        'excluded_objects':{n:h for n,h in obj_hash.items() if n not in linked},
        'architecture_difference':'No native SendForm/platform/HII/discovery. Test-only console owner/token adapter replaces platform_session_owned/platform_can_enter/end_platform. Real production services AP_ENV read/persist, UI and password core are unchanged.',
        'efi_path':str(efi),'efi_sha256':sha(efi),'efi_bytes':efi.stat().st_size,
        'iso_path':str(iso_path) if iso_path else None,'iso_sha256':sha(iso_path) if iso_path else None,
        'iso_created':bool(iso_path),'source_bundle_sha256':bundle,'local_sources':local,'external_sources':external,
        'generated_sources':{f.name:sha(f) for f in sorted(src.iterdir()) if f.is_file()},
        'stage1_receipt_binding':receipt,'hardware_tested':False,'physical_firmware_writes_performed_by_builder':False,
        'writes_if_deployed':'Only AiTweakerPassword1904/750e9d9d-f2d8-4e14-9b53-8923a7190461 via saved native SetVariable; this is NOT RAM-only. Firmware may internally update flash as normal NVRAM implementation.',
        'limitations':['No complete Setup/native owner/UI integration claim.','Only runtime-table/API paths are guarded; no SMM/cached-pointer/whole-SPI rollback claim.',
          'Stage 2 cannot be built before a real stage-1 receipt is supplied.','Interrupted changed/disabled records are never auto-adopted or arbitrarily deleted.',
          'Application stays resident; final EBS/ResetSystem attempts halt locally and external power-off is required.'],
        'commands':commands}
    (out/'build.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:result[k] for k in ['status','build_id','efi_sha256','iso_sha256','production_object_relink_exact_match']},indent=2))
if __name__=='__main__':main()
