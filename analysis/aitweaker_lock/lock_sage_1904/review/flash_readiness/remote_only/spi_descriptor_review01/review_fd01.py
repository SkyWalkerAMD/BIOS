"""Independent FD01 audit binder. Read artifacts, write this review only.

No firmware/device/network calls, test reruns, candidate edits, or deployment.
"""
from pathlib import Path
import datetime, hashlib, io, json, re, struct, sys, warnings, zipfile
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
REMOTE=HERE.parent
CASE=REMOTE.parents[2]
ROOT=CASE.parents[2]
CAND=REMOTE/'spi_descriptor_candidate01'
for folder in ['pydeps','vm-pydeps','kvm-pydeps']:
    sys.path.insert(0,str(ROOT/'tools'/folder))
warnings.filterwarnings('ignore',message='pkg_resources is deprecated.*')
import pefile, pycdlib
from pyfatfs.PyFatFS import PyFatFS
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(data):return hashlib.sha256(data).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def ref(p):return {'path':str(p),'sha256':sha(p)}
def excerpt(p,start,end):
    lines=p.read_text(encoding='utf8').splitlines()
    end=min(end,len(lines))
    return {**ref(p),'first_line':start,'last_line':end,'lines':[{'line':i+1,'text':lines[i]} for i in range(start-1,end)]}

expected='20a9c111dc048805b62261bdee7438a573a0a5a2846d2a57bc4f6cfbda4c3c48'
efi=CAND/'build/BOOTX64.EFI';iso=CAND/'build/SAGE1904-SPI-DESCRIPTOR01.iso'
build=read(CAND/'build/build.json')
manifest=read(CAND/'candidate_manifest.json')
for item in manifest['artifact_bindings']:
    path=Path(item['path'])
    assert path.stat().st_size==item['bytes'] and sha(path)==item['sha256'],str(path)
assert sha(efi)==expected==build['efi_sha256']
assert sha(iso)==build['iso_sha256']
for name,h in build['source_files'].items():assert sha(CAND/name)==h,name
archive=CAND/'build/source-snapshot.zip'
assert sha(archive)==build['source_archive_sha256']
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert all(digest(z.read(name))==h for name,h in build['source_files'].items())
cd=pycdlib.PyCdlib();cd.open(str(iso));efi_buf=io.BytesIO();boot_buf=io.BytesIO()
cd.get_file_from_iso_fp(efi_buf,iso_path='/EFI/BOOT/BOOTX64.EFI;1')
cd.get_file_from_iso_fp(boot_buf,iso_path='/EFIBOOT.IMG;1')
platform_id=cd.eltorito_boot_catalog.validation_entry.platform_id
cd.close()
assert platform_id==0xef and efi_buf.getvalue()==efi.read_bytes()
boot=CAND/'build/eltorito.img'
assert boot_buf.getvalue()==boot.read_bytes()
with PyFatFS(str(boot),read_only=True,utc=True) as fat:
    assert fat.readbytes('/EFI/BOOT/BOOTX64.EFI')==efi.read_bytes()

pdf=HERE/'Intel-743845-001.pdf'
assert sha(pdf)=='9d6491fec3cda0b6709f2fc815e236a0052776bd638e5f14bb3917addeabad9c'
cpu=REMOTE/'cpuio2_native/OriginalCpuIo2.efi'
assert sha(cpu)=='4fe8ca3ca86616c659a55f6a9faac1a2c511dde1de7996a7c46dba8559422f24'
np=pefile.PE(str(cpu))
header=(CAND/'source/cpu_reference.h').read_text(encoding='utf8')
arrays={}
for name,rva,count in [('cpu_reference_code',0x30c,0x228),('cpu_reference_tables',0x750,0x1c)]:
    body=re.search(r'\b'+name+r'\[\]\s*=\s*\{([^}]+)\}',header).group(1)
    data=bytes(int(x,16) for x in re.findall(r'0x([0-9a-f]+)',body))
    assert len(data)==count and data==np.get_data(rva,count)
    arrays[name]={'original_rva':hex(rva),'bytes':count,'sha256':digest(data)}
assert np.get_data(0x44c,2).hex()=='8b03'
assert np.get_data(0x4fe,2).hex()=='8903'

tests={}
for report_name,test_name in [('core_regression.json','verify_core.py'),('frontend_regression.json','verify_frontend.py'),('transport_regression.json','verify_transport.py'),('build/ovmf_verification.json','verify_ovmf.py')]:
    p=CAND/report_name;r=read(p);assert r['efi_sha256']==expected
    test_hash=r.get('verification_source_sha256',r.get('test_source_sha256'))
    assert sha(CAND/test_name)==test_hash
    assert r['status'].startswith('PASS')
    if isinstance(r.get('cases'),list):
        assert all(x.get('passed') is True or x.get('status','').startswith('PASS') for x in r['cases'])
    tests[report_name]={'report':ref(p),'test_source':ref(CAND/test_name),'status':r['status'],
                        'case_count':r.get('case_count'),'scope':r.get('tested_scope',r.get('scope')),'limits':r.get('limits')}
core=read(CAND/'core_regression.json');front=read(CAND/'frontend_regression.json')
for item in front['cases']:assert sha(Path(item['log']))==item['log_sha256']
assert core['source_sha256']==sha(CAND/'source/fd_core.c')
assert front['native_cpuio2_sha256']==sha(cpu)
assert core['cases'][0]['result']['go_attempts']==128
assert core['cases'][0]['result']['writes']==386
assert front['cases'][0]['read_cycles']==128 and front['cases'][0]['mmio_writes']==386
transport=read(CAND/'transport_regression.json')
assert transport['input_log_sha256']==front['cases'][0]['log_sha256']
assert transport['dll_sha256']==sha(CAND/'build/qr_test.dll')
assert transport['qr_pages']==15 and transport['roundtrip_identical']
assert transport['missing_and_corrupt_page_rejected']
ovmf=read(CAND/'build/ovmf_verification.json')
assert ovmf['iso_sha256']==sha(iso)
for case in ovmf['cases']:
    assert case['efi_sha256']==expected and case['iso_sha256']==sha(iso)
    assert sha(CAND/case['folder']/'RESTORED-LOG.TXT')==case['restored_log_sha256']
parser=CASE/'remote_172_20_2_162/read_spi_descriptor01_qr.py'
parser_report=read(CAND/'parser_regression.json')
assert sha(parser)==parser_report['parser_sha256']
assert parser_report['input_log_sha256']==front['cases'][0]['log_sha256']
tests['parser_regression.json']={'report':ref(CAND/'parser_regression.json'),'parser_source':ref(parser),'status':parser_report['status'],'case_count':parser_report['cases'],'limit':'Reviewed parser and result digest; this reviewer did not repeat its seven-case execution.'}

pe=pefile.PE(str(efi));assert pe.verify_checksum() and pe.OPTIONAL_HEADER.Subsystem==10
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT')
base=pe.OPTIONAL_HEADER.ImageBase;image=pe.get_memory_mapped_image()
syms={}
for line in (CAND/'build/inventory.map').read_text(encoding='utf8').splitlines():
    m=re.match(r'\s*0001:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{16})\s',line)
    if m:syms[m[1]]=int(m[2],16)
ordered=sorted(set(syms.values()));md=Cs(CS_ARCH_X86,CS_MODE_64)
native={}
for name in ['native_binding','io_read','io_write','io_binding','fd_capture','snapshot','get_idle','same_snapshot','ack_done']:
    start=syms[name];end=next(x for x in ordered if x>start);raw=image[start-base:end-base]
    native[name]={'rva':hex(start-base),'extent_to_next_link_symbol':len(raw),'sha256':digest(raw),
                  'instructions':[{'rva':hex(i.address-base),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(raw,start)]}

report={
 'schema':1,'status':'INDEPENDENT_OFFLINE_REVIEW_NO_BLOCKING_CODE_DEFECT_IDENTIFIED_FOR_FIXED_FD_READ',
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'reviewer':'/root/sage_remote_identity',
 'scope':'Only FD01 fixed two-pass4096-byte diagnostic READ; not the password driver, a complete SPI backup, restoration, or firmware flashing.',
 'review_actions':{'devices_accessed':False,'BMC_accessed':False,'new_public_network_calls':False,'candidate_source_or_binary_changed':False,'original_tests_rerun':False,'artifact_and_packaging_digests_independently_checked':True,'original_CPU_reference_bytes_independently_checked':True,'manual_PDF_pages_visually_reviewed':[396,397,398,399,400]},
 'candidate':{'EFI':ref(efi),'ISO':ref(iso),'candidate_manifest':ref(CAND/'candidate_manifest.json'),'validated_candidate_manifest_bindings':len(manifest['artifact_bindings']),'build_manifest':ref(CAND/'build/build.json'),'sources_manifest':ref(CAND/'sources.json'),'source_archive':ref(archive),'source_files':build['source_files']},
 'packaging_checks':{'source_archive_all_entries_match_manifest':True,'ISO_top_level_EFI_exact':True,'ISO_boot_image_exact':True,'ElTorito_platform_id':'0xEF','FAT_UEFI_fallback_EFI_exact':True,'FAT_opened_read_only':True,'PE_checksum_valid':True,'PE_subsystem':10,'PE_imports_absent':True},
 'blocking_findings':[],
 'conclusion':{'normal_input_or_failpath_blocker_found':False,'fixed_READ_only_execution_supported_by_review':True,'physical_acceptance_established':False,'guaranteed_exclusive_controller_ownership':False,'full_SPI_backup_established':False,'firmware_flash_or_update_approved_by_this_review':False,'qualification':'The reviewed artifact is suitable for considering a bounded diagnostic attempt under its existing gates. This static/test-evidence conclusion is not a guarantee of real-controller completion or permission to perform a firmware update.'},
 'manual':{**ref(pdf),'section':'7.2.2 BIOS_HSFSTS_CTL and7.2.3 BIOS_FADDR','pages':[396,397,398,399,400],
   'visual_pages':[ref(HERE/n) for n in ['independent-register-map-0396.png','independent-register-width-0397.png','Intel-registers-0398.png','Intel-registers-0399.png','Intel-registers-0400.png']],
   'observations':['p396 maps HSFSTS_CTL at4..7,FADDR8..B,DLOCKC..F,FDATA10..4F,FRACC50,FREG054,FPR084..94,GPR098. GPR0 is a documented register rather than a guessed extension.',
    'p397 describes HSFSTS_CTL as a32-bit memory register; p400 describes FADDR as32-bit, low27bits RW and high5bits reserved RO.',
    'p398 defines READ as FCYCLE0 and64bytes as FDBC63. WET and FSMIE are RW and remain zero under the candidate precondition.',
    'p399 states FGO reads zero, initiates a cycle on write1, and allows transaction parameters in that same write. SCIP must be zero before another command. FLOCKDN cannot be cleared without hardware reset; WRSDIS is locked when FLOCKDN is set; PRR34_LOCKDN is also sticky once set.',
    'p400 defines FDONE,FCERR,AEL as write-one-to-clear. The candidate never clears AEL/FCERR: it refuses them, and acknowledges only observed FDONE while idle.'],
   'prior_progress_resolution':'Earlier progress_review.json correctly left low-byte W1C unproved. FD01 instead uses documented DWORD access; this review does not convert that old uncertainty into a byte-access claim.'},
 'findings':[
  {'id':'FD01-READ-WHITELIST','classification':'OBSERVED_SOURCE_AND_COMPILED_PATH','finding':'io_write accepts only offsets4 and8. Every write with FGO1 must equal0x3F01E800, and independently reads FADDR to require a64-aligned address below4096. Core issues64blocks for each of2passes. Thus each executed command is READ64 covering0..0xFFF. FDATA is read only; FDOC, SW sequencing, PCI writes and other SPI operations have no reachable call here.','source':['source/fd_core.c:65','source/fd_core.c:73','source/fd_core.c:85','source/inventory.c:205'],
   'boundary':'Non-GO control writes can retain/restore an old FCYCLE value; without FGO they do not issue that command. Restoring original FADDR may set an address outside0..0xFFF but is never followed by another GO.'},
  {'id':'FD01-PROTECTION-STATE','classification':'OBSERVED_SOURCE_PLUS_MANUAL','finding':'status_valid requires low locked state0xE800, rejects reserved/error/busy states as appropriate and rejects FSMIE/WET/FGO on reads. Writes reproduce the existing low protection fields. Snapshots bind DLOCK, FRAP0x4ACF, FREG0=0, PR0..4=0 and GPR0=0; PCI identity and BIOS_CNTL0x100008AA are rechecked before each block.','source':['source/fd_core.c:35','source/fd_core.c:39','source/fd_core.c:50','source/inventory.c:190'],
   'wording_correction':'Zero flash program/erase does not mean zero MMIO writes. DWORD writes physically include lock fields at their already-validated values. They preserve protection state; they do not avoid touching those bit positions.'},
  {'id':'FD01-FAIL-STOP','classification':'OBSERVED_SOURCE_AND_REVIEWED_EMULATION','finding':'Any failed read/write/binding, stale address/status, changed protection, SPI error, or uncompleted10000-poll budget returns immediately. No cleanup write is attempted on ambiguous start/completion. Transient restoration is entered only after128completedblocks, final idle/FDONE acknowledgement and successful binding.','source':['source/fd_core.c:65','source/fd_core.c:84','source/fd_core.c:105'],
   'boundary':'Polling is bounded by10000iterations with10us Stall requests plus execution overhead, not a hard wall-clock100ms guarantee. On failure, transient fields can deliberately remain unrestored; logs expose that fact.'},
  {'id':'FD01-CPU-PROVIDER','classification':'OBSERVED_ORIGINAL_BYTES_AND_REVIEWED_NATIVE_EMULATION','finding':'Both methods must occupy code mappings, be separated by0xB0 and match the entire original validator/Read/Write block plus stride tables. The source reference bytes match the original ASUS image exactly. The full frontend tests execute that image at Mem.Read loadRVA0x44C and Mem.Write storeRVA0x4FE, asserting DWORD size; those methods are not modeled as success-only stubs.','source':['source/inventory.c:150','source/inventory.c:175','source/inventory.c:181','verify_frontend.py:mmread','verify_frontend.py:mmwrite'],'reference_arrays':arrays,
   'boundary':'UEFI/PCI and device state are modeled. The live interface must independently pass the runtime fingerprint; no previous INV04 read acceptance is inherited as a write-path hardware pass.'},
  {'id':'FD01-DATA-EXPORT','classification':'OBSERVED_SOURCE_AND_REVIEWED_TRANSPORT','finding':'The core completes both4096-byte passes, restores permitted transient fields, checks unchanged protection, compares every byte and verifies descriptor signature before returning success. Only success exports128ordered32-byte rows. Failure logs export no descriptor. The current15-page synthetic QR roundtrip preserves10983bytes; missing/corrupt pages are rejected.','source':['source/fd_core.c:105','source/fd_core.c:118','source/inventory.c:238','parser:parse_descriptor'],
   'boundary':'The4KiB descriptor and its configured density are not a complete SPI dump, JEDEC/SFDP identity check or remote recovery proof.'},
  {'id':'FD01-OVMF-SCOPE','classification':'REVIEWED_TEST_ARTIFACTS','finding':'The2OVMF cases and18checks prove boot/display/QR/exit and refusal on absent target identity/controller. They do not emulate the W790 SPI controller and are not evidence of a physical positive capture.'},
  {'id':'FD01-CONCURRENCY','classification':'REMAINING_PLATFORM_LIMIT_NOT_OBSERVED_FAILURE','finding':'Snapshots and repeated binding are point-in-time checks. The program does not establish an SMM/other-master mutex, so an external actor could change controller state between checks. No such interference is demonstrated by the supplied evidence; this is retained as a limit rather than an invented observed blocker.'}
 ],
 'test_evidence':{'reviewed_reports':tests,'normal_core':core['cases'][0],'normal_full_frontend':front['cases'][0],'core_cases':core['case_count'],'frontend_cases':front['case_count'],'transport_pages':transport['qr_pages'],'OVMF_cases':len(ovmf['cases']),'OVMF_checks':sum(len(c['checks']) for c in ovmf['cases']),'parser_checks':parser_report['cases'],
  'reviewer_execution_limit':'Author suites were read and their hashes/results validated; this audit did not rerun them or perform a new hardware experiment. Native bytes and package contents were independently inspected.'},
 'source_excerpts':{
  'core':excerpt(CAND/'source/fd_core.c',25,121),
  'provider_and_IO':excerpt(CAND/'source/inventory.c',175,220),
  'export_and_entry':excerpt(CAND/'source/inventory.c',237,287)
 },
 'native_evidence':native,
 'artifacts_unchanged_after_review':{'efi':sha(efi)==expected,'source_manifest':all(sha(CAND/n)==h for n,h in build['source_files'].items()),'ISO':sha(iso)==build['iso_sha256']},
 'original_CPU_IO2':ref(cpu),'review_builder':ref(Path(__file__))
}
out=HERE/'fd01_independent_review.json'
out.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print(json.dumps({'report':str(out),'sha256':sha(out),'status':report['status'],'efi_sha256':expected,'blocking_findings':len(report['blocking_findings'])},indent=2))
