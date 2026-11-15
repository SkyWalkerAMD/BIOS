"""Independent source and immutable-artifact review of the read-only sampler.

Does not call UEFI or execute the sample. It writes only this review report.
"""
from pathlib import Path
import hashlib,json,sys,zlib

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
D=HERE.parent/'diagnostic_native01'
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))

build=read(D/'build/build.json')
efi=D/'build/BOOTX64.EFI';iso=D/'build/W890-NATIVE-SAMPLE01-NOFLASH.iso'
assert sha(efi)==build['efi_sha256']=='7bad5e1b48b4e1bcb076f1f46541ce5036dac4e2e000b5fd193c79c2e4524fb1'
assert sha(iso)==build['iso_sha256']=='afef8c4120c59ab9985f3bc5044d2002ef9f75460e99329c9d53664722db0b81'
source_bindings=[]
for name,digest in build['sources'].items():
    p=D/'source'/name;assert sha(p)==digest;source_bindings.append(binding(p))
for name in ('native_sample.c','native_sample.h','native_bridge.c'):
    assert (D/name).read_bytes()==(D/'source'/name).read_bytes()
bridge=(D/'native_bridge.c').read_text();sample=(D/'native_sample.c').read_text()
probe=(D/'source/probe.c').read_text()
entry=bridge[bridge.index('int native_read_only('):]
assert entry.index('ES status=((GET_MAP)')<entry.index('!ns_range(memory_map')<entry.index('ap_sha256(')
assert 'if(!native_read_only(st,w890_tse,w890_setup,emit))warnings++;' in probe
assert 'NATIVE_SAMPLE_STATUS=INACTIVE\\r\\n");return 0;' in bridge
tests=read(D/'build/sample_tests.json')
assert tests['passed'] and tests['cases']==len(tests['checks'])==58 and all(x['passed'] for x in tests['checks'])
assert sha(D/'native_sample.c')==tests['source_sha256'] and sha(D/'native_sample.h')==tests['header_sha256']
assert sha(D/'build/native_sample_test.dll')==tests['dll_sha256']
efi_tests=read(D/'build/efi_tests.json')
assert efi_tests['passed'] and efi_tests['efi_sha256']==sha(efi) and len(efi_tests['cases'])==9
assert all(x['passed'] and x['module_memory_unchanged'] and x['filesystem_calls']==x['runtime_service_calls']==0 for x in efi_tests['cases'])
vm_dir=D/'build/vm/sata_800x600';vm=read(vm_dir/'result.json');restored=(vm_dir/'RESTORED-LOG.TXT').read_bytes()
assert vm['passed'] and vm['efi_sha256']==sha(efi)
assert vm['iso_sha256_before']==vm['iso_sha256_after']==sha(iso)
assert vm['qr_restoration']['sha256']==hashlib.sha256(restored).hexdigest()
assert vm['qr_restoration']['bytes']==len(restored) and vm['qr_restoration']['crc32']==f'{zlib.crc32(restored)&0xffffffff:08X}'
pe=pefile.PE(str(efi))
assert pe.verify_checksum() and pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size>0
report=dict(status='REVIEWED_NO_OPEN_SOURCE_READING_DEFECT_FOUND_WITHIN_SCOPE',
    firmware_release_ready=False,hardware_test_performed_by_reviewer=False,
    scope='Added native_sample.c/.h, native_bridge.c, generated probe glue and pinned build outputs; source review, not hardware or authorization proof.',
    artifact_bindings=[binding(efi),binding(iso),binding(D/'build/build.json'),binding(D/'build.py')],
    source_bindings=source_bindings,
    review_findings=[
        dict(id='NSR01',severity='read-guard gap',status='RESOLVED_IN_BOUND_BUILD',
             initial='Bridge performed large text SHA reads before fetching and checking the memory map.',
             resolution='Memory map is fetched first; both entire original text spans pass ns_range before SHA. Overflow of base plus 4096 is refused.'),
        dict(id='NSR02',severity='misleading completeness',status='RESOLVED_IN_BOUND_BUILD',
             initial='Native sampler refusal or inactivity could leave the top-level collection marked complete.',
             resolution='All unavailable/refusal/inactive paths return zero; generated probe increments warnings and presents partial collection.'),
    ],
    reviewed_checks=[
        'Loaded-image W890 GUID and exact CRC/text span/entry/image size select candidate bases; separate SHA256 of unchanged text must match.',
        'AMITSE base is page aligned and constrained to lower canonical addresses; fixed image size bounds all sampled globals.',
        'Memory descriptors require version 1, bounded stride/count/byte size, checked page arithmetic and non-overlapping containment of each read.',
        'Only loader, boot-service or runtime-service code/data descriptor types are accepted; advertised read protection causes refusal.',
        'Each pointer chain read uses NS_COPY; app, selected slot and page sizes are fixed and bounded; counts/index arithmetic are checked.',
        'Application, pointer slot, selected page and globals are reread and compared before stable status is emitted.',
        'Native HII/history/frame/extra values are logged as opaque metadata; their contents are not dereferenced by the sampler.',
        'No new SetVariable, flash, hook installation, firmware code write, credential read/write or password rendering call was found.',
    ],
    reported_tests=dict(binding=binding(D/'build/sample_tests.json'),cases=58,
        independently_rerun_by_reviewer=False,scope=tests['scope'],
        actual_efi_tests=binding(D/'build/efi_tests.json'),actual_efi_case_count=9,
        ovmf=binding(vm_dir/'result.json'),restored_log=binding(vm_dir/'RESTORED-LOG.TXT'),
        restored_log_crc_independently_rechecked=True,
        limitation='Tests executed by root. Reviewer verified exact artifact binding, case outcomes and restored log bytes/CRC; did not re-execute the VM.'),
    still_required_before_hardware=[
        'Original target profile remains W890 0603 and sampler is used as read-only inventory only.'],
    limits=[
        'MemoryMap descriptors and attributes do not prove current page-table accessibility or live object ownership; a physical read still depends on the host firmware memory contract.',
        'Double sampling detects sampled changes but not ABA, asynchronous lifetime changes or a whole-BrowserLoop lock. It must never grant mutation authority.',
        'Pre-existing P3 LoadedImage/device-path/HII protocol traversal trusts firmware-owned protocol outputs; this review does not claim complete proof of all inherited firmware data lifetimes.',
        'This application may see an inactive native application after Boot Override. That outcome is partial diagnostic evidence, not a failure to be bypassed.',
        'No actual Ai Tweaker gate, independent password UI or persistent password lock is installed by this ISO.',
    ])
(HERE/'native_sampler_review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=report['status'],source_bindings=len(source_bindings),sha256=sha(HERE/'native_sampler_review.json'))))
