"""Review stage-2-only build differences against the frozen stage-1 medium."""
from pathlib import Path
import difflib,hashlib,io,json,re,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;CASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
for name in ['pydeps','vm-pydeps','kvm-pydeps']:sys.path.insert(0,str(ROOT/'tools'/name))
import pefile,pycdlib,capstone as C
from pyfatfs.PyFatFS import PyFatFS
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
one=CASE/'stage1/build';two=HERE/'build'
a=json.loads((one/'build.json').read_text(encoding='utf8'));b=json.loads((two/'build.json').read_text(encoding='utf8'))
checks=[]
def check(name,value):assert value,name;checks.append(name)
check('stage1 manifest remains frozen',sha(one/'build.json')=='7fabb0521a042fd718a957df2733fd3dd6b20711fbd38f14d45772f7002818c5')
check('stage1 original EFI/ISO remain unchanged',sha(a['efi_path'])==a['efi_sha256']=='dfc5b8e413399c6c003076fdbeca1ec653c8d3557320b41916064fbf6a4bd2c1' and sha(a['iso_path'])==a['iso_sha256']=='381ecb4d856dfa5cb99709a488102964b8641748ec357b8a0459bd2d15367b92')
check('stage2 expected EFI/ISO identity',sha(b['efi_path'])==b['efi_sha256']=='42edb22f88f4c84adadbe01777ed5afd4840a27a80227a596ba3f1cc220472ef' and sha(b['iso_path'])==b['iso_sha256']=='ddf12d26608734c71e715dbe7f6cc4b5cd8e7a6d1055eefc7f1cf5b88f8bfc9d')
check('same exact production relink',a['production_object_relink_exact_match'] and b['production_object_relink_exact_match'] and sha(two/'PRODUCTION-RELINK-CHECK.EFI')==a['production_driver_sha256']==b['production_driver_sha256'])
for key in ['local_sources','production_sources','production_external_sources','all_production_object_hashes','linked_objects','excluded_objects','external_sources','source_bundle_sha256']:
    check('stage2 retains identical '+key,a[key]==b[key])
check('local source files remain unchanged',all(sha(CASE/p)==h for p,h in a['local_sources'].items()))
receipt=b['stage1_receipt_binding'];record='c1d706f63848951af3c28e6378d719ea6ebd509adabb69a700060be84ae57379';logsha='a47b5a24e3cd978e895bac63e40cf2095d535098e752b474457cf481d2cfe54b'
check('actual hardware receipt file and explicit hash match',sha(receipt['log_path'])==receipt['log_sha256']==logsha)
check('record hash and original stage1 EFI/manifest bound',receipt['record_sha256']==record and receipt['manifest_sha256']==sha(one/'build.json') and receipt['stage1_efi_sha256']==a['efi_sha256'])
header=(two/'source/build_identity.h').read_text(encoding='ascii')
check('generated stage constant is 2',re.search(r'^#define NV_STAGE 2u$',header,re.M) is not None)
embedded=bytes(map(int,re.search(r'NV_EXPECTED_RECORD\[32\]=\{([^}]+)\}',header)[1].split(',')))
check('generated expected bytes exactly match physical receipt record hash',embedded.hex()==record)
check('generated receipt log SHA exactly matches actual first stage',('#define NV_RECEIPT_LOG_SHA "'+logsha+'"') in header)
diffs=[]
for name in a['generated_sources']:
    left=(one/'source'/name).read_text(encoding='utf8');right=(two/'source'/name).read_text(encoding='utf8')
    if left!=right:diffs.extend(difflib.unified_diff(left.splitlines(True),right.splitlines(True),fromfile='stage1/'+name,tofile='stage2/'+name))
(HERE/'generated_source_diff.txt').write_text(''.join(diffs),encoding='utf8')
check('unchanged target detection source',a['generated_sources']['target_detect.h']==b['generated_sources']['target_detect.h'])
normalized={}
for name in ['nv_guard.obj','qrcodegen.obj']:
    x=(one/name).read_bytes();y=(two/name).read_bytes();norm=lambda raw:raw[:4]+bytes(4)+raw[8:]
    check(name+' identical except standard COFF timestamp',norm(x)==norm(y))
    normalized[name]={'stage1_sha256':sha(one/name),'stage2_sha256':sha(two/name),'timestamp_normalized_sha256':hashlib.sha256(norm(x)).hexdigest(),'different_offsets':[i for i,(v,w) in enumerate(zip(x,y)) if v!=w]}
pe=pefile.PE(b['efi_path']);mapped=pe.get_memory_mapped_image();base=pe.OPTIONAL_HEADER.ImageBase
check('stage2 PE is valid unsigned relocatable EFI application',pe.OPTIONAL_HEADER.Subsystem==10 and pe.verify_checksum() and not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)
check('actual EFI contains expected record hash once',mapped.count(bytes.fromhex(record))==1)
check('actual EFI contains bound receipt log SHA',logsha.encode() in mapped)
symbols={n:int(v,16) for n,v in re.findall(r'^\s+[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{16})\s',(two/'nv_test.map').read_text(encoding='utf8'),re.M)}
cs=C.Cs(C.CS_ARCH_X86,C.CS_MODE_64);cs.detail=True
start=symbols['efi_main'];end=min(v for v in symbols.values() if v>start)
instructions=list(cs.disasm(mapped[start-base:end-base],start))
call_index=next(i for i,x in enumerate(instructions) if x.mnemonic=='call' and x.operands[0].type==C.CS_OP_IMM and x.operands[0].imm==symbols['nv_prepare'])
window=instructions[max(0,call_index-14):call_index+1]
check('actual efi_main passes phase2 to nv_prepare',any(x.mnemonic=='mov' and x.op_str=='r8d, 2' for x in window))
hash_addr=None
for x in window:
    if x.mnemonic=='lea' and x.reg_name(x.operands[0].reg)=='r9' and x.operands[1].type==C.CS_OP_MEM and x.reg_name(x.operands[1].mem.base)=='rip':hash_addr=x.address+x.size+x.operands[1].mem.disp
check('actual efi_main passes real record hash address to nv_prepare',hash_addr is not None and mapped[hash_addr-base:hash_addr-base+32]==bytes.fromhex(record))
pe.close();iso=pycdlib.PyCdlib();iso.open(b['iso_path']);payload=io.BytesIO();iso.get_file_from_iso_fp(payload,iso_path='/EFIBOOT.IMG;1');iso.close()
check('stage2 El Torito image is exact generated FAT image',payload.getvalue()==(two/'eltorito.img').read_bytes())
with PyFatFS(str(two/'eltorito.img'),read_only=True) as fat:inside=fat.readbytes('/EFI/BOOT/BOOTX64.EFI')
check('stage2 ISO boot EFI exactly equals reviewed EFI',inside==Path(b['efi_path']).read_bytes())
smoke=json.loads((two/'boot_validation.json').read_text(encoding='utf8'))
check('stage2 non-target refusal smoke binds exact media',smoke['efi_sha256']==b['efi_sha256'] and smoke['iso_sha256']==b['iso_sha256'] and all(c['passed'] for c in smoke['cases']))
result={'status':'PASS_REAL_RECEIPT_BOUND_STAGE2_MINIMAL_DELTA','checks':len(checks),'check_names':checks,
        'efi_sha256':b['efi_sha256'],'iso_sha256':b['iso_sha256'],'production_driver_sha256':b['production_driver_sha256'],
        'stage1_manifest_sha256':sha(one/'build.json'),'stage2_manifest_sha256':sha(two/'build.json'),
        'stage1_receipt':receipt,'unchanged_normalized_objects':normalized,
        'nv_prepare_call_disassembly':[{'address':hex(x.address),'instruction':x.mnemonic+' '+x.op_str} for x in window],
        'diff_path':str((HERE/'generated_source_diff.txt').relative_to(ROOT)),'diff_sha256':sha(HERE/'generated_source_diff.txt'),
        'source_sha256':sha(Path(__file__)),'stage2_hardware_tested':False,
        'reused_tests':'Unchanged production core/services/gate code retains stage1 82 gate and 20 real PBKDF/persistence-chain local tests; new stage constants and receipt bytes verified in actual EFI.',
        'physical_persistence_not_claimed_by_this_build':True}
(HERE/'review_delta.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps({k:result[k] for k in ['status','checks','efi_sha256','iso_sha256']},indent=2))
