"""Independent scope, frozen identities and entry-authority review of recovery03.

The OVMF and DPAPI functional runs are attributed to the password agent. This
review never decrypts the journal, opens a device or writes a firmware variable.
"""
from pathlib import Path
import ast, hashlib, io, json, re, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BOARD=HERE.parent;ROOT=HERE.parents[3]
D=BOARD/'password_recovery03';RUN=D/'lab/runs/20261108_014611'
sys.path[:0]=[str(ROOT/'tools/pydeps'),str(ROOT/'tools/kvm-pydeps')]
import pefile,pycdlib
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def binding(p):return dict(path=str(p.resolve()),size=p.stat().st_size,sha256=sha(p))

mp=D/'component_manifest.json';m=read(mp)
assert sha(mp)=='303cb2ba72eadd23e31f53d967a7d246071eef950a447648ec54294ae53f2d88'
assert m['status']=='FROZEN_IDENTITY_READONLY_RECOVERY_CARRIER_FOR_REVIEW'
assert not m['release_ready'] and not m['hardware_smbios_identity_observed'] and not m['hardware_writer_exclusion_authority'] and m['physical_operations']==0
checked=[];assert len(m['bindings'])==62
for name,e in m['bindings'].items():
    p=(D/name).resolve();assert p.is_relative_to(D.resolve())
    assert p.stat().st_size==e['bytes'] and sha(p)==e['sha256'];checked.append(binding(p))
for name,e in m['frozen_dependencies'].items():
    dep=BOARD/name/'component_manifest.json';assert sha(dep)==e['manifest_sha256']
build=read(D/'build/build.json');assert build['component']==m['component']
efi=D/'build'/build['component']['file'];lab=D/'build'/build['lab']['file']
assert sha(efi)==build['component']['sha256']=='96dc509c8cc6b5db746b97f3a97562c8d2ab6b31f688ffc5e06cc1463f8760ff'
assert efi.stat().st_size==29696
assert sha(lab)==build['lab']['sha256']=='96f51615f473785b3aa0b0ba409220cec879dd071ccd399bf0a92f4971f04974'
pe=pefile.PE(str(efi));assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==10
assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size==0
assert not any(s.Characteristics&0xa0000000==0xa0000000 for s in pe.sections)
for key in ['sources','lab_sources']:
    for name,digest in build[key].items():
        assert sha(D/name)==digest and sha(RUN/'inputs'/name)==digest
for e in build['module_source_binding']:
    p=ROOT/e['source'];assert sha(p)==e['original_sha256']
    ppe=pefile.PE(str(p));text=next(s for s in ppe.sections if s.Name.rstrip(b'\0')==b'.text')
    assert hashlib.sha256(text.get_data()[:text.Misc_VirtualSize]).hexdigest()==e['text_sha256']

vm=read(RUN/'result.json')
assert vm['status']=='PASS_REAL_OVMF_RECOVERY_AND_DPAPI_KEYBOARD_HANDOFF' and vm['exit_code']==33
assert vm['component_sha256']==sha(efi) and vm['lab_sha256']==sha(lab)
assert vm['build_sha256']==sha(D/'build/build.json')==sha(RUN/'inputs/build.json')
assert sha(RUN/'inputs'/efi.name)==sha(efi) and sha(RUN/'inputs'/lab.name)==sha(lab)
assert sha(RUN/'debug.log')==vm['debug_sha256'] and sha(RUN/'vars.fd')==vm['vars_sha256']
iso=RUN/'recovery03-lab.iso';assert sha(iso)==vm['iso_sha256_before']==vm['iso_sha256_after']
assert vm['physical_operations']==0 and not vm['qmp_key_payloads_logged'] and vm['no_plaintext_password_in_debug']
debug=(RUN/'debug.log').read_text(encoding='ascii');log=debug[debug.index('RECOVERY03_LAB_BEGIN\n'):]
assert log.endswith('RECOVERY03_LAB_PASS\n') and 'FAIL ' not in log
assert len(re.findall(r'^PASS ',log,re.M))==vm['check_count']==28
for marker in ['actual OVMF identity cannot authorize ASUS recovery','matching identity is insufficient without writer-exclusion proof',
               'actual read-only UI asks for no password and writes nothing','cancel restores original full framebuffer',
               'real keyboard DPAPI handoff authenticates and deletes only exact record','real NV confirms credential absent after recovery',
               'unrelated variable remains unchanged','event closure verified before carrier may return to loader']:
    assert 'PASS '+marker+'\n' in log
behavior=read(D/'build/recovery_pe_tests.json');handoff=read(D/'build/handoff_tests.json')
assert behavior['status']=='PASS_ACTUAL_RECOVERY03_EFI_MODELED_BOUNDARIES' and behavior['case_count']==len(behavior['cases'])==54
assert all(c['status']=='PASS' for c in behavior['cases']) and behavior['efi_sha256']==sha(efi)
assert behavior['source_sha256']==sha(D/'verify_recovery_pe.py') and behavior['inherited_fixture_sha256']==sha(BOARD/'password_runtime02/verify_runtime_pe.py')
assert handoff['status']=='PASS_ACTUAL_DPAPI_HANDOFF_VALIDATION_MODEL_KEY_SINK' and handoff['case_count']==len(handoff['cases'])==8
assert handoff['handoff_source_sha256']==sha(D/'handoff.py')==sha(RUN/'inputs/handoff.py')
assert behavior['physical_operations']==handoff['physical_or_bmc_operations']==0

# Reuse only the three pure FAT helpers from the separately reviewed checker;
# do not execute that checker's top-level code or rewrite its output.
helper_path=HERE/'review_hii_lab.py';tree=ast.parse(helper_path.read_text(encoding='utf-8'))
nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'u16','u32','fat16_file'}]
assert len(nodes)==3
helpers={'struct':struct};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(helper_path),'exec'),helpers)
cd=pycdlib.PyCdlib();cd.open(str(iso));boot=io.BytesIO();cd.get_file_from_iso_fp(boot,iso_path='/EFIBOOT.IMG;1');cd.close()
assert boot.getvalue()==(RUN/'boot.img').read_bytes()
assert helpers['fat16_file'](boot.getvalue(),[b'EFI        ',b'BOOT       ',b'BOOTX64 EFI'])==lab.read_bytes()

entry=(D/'source/entry.c').read_text();services=(D/'source/services.c').read_text()
assert 'rc_initialize(st,0,0,0)' in entry and entry.count('if(!rc_shutdown())rc_hold_resident();')==2
assert 'if(!rc_alive()||rc_identity()!=3||!rc_alive()||!boot_proof||!proof_epoch' in services
assert 'if(first[12]!=1){result=RC_DENIED;goto done;}' in services
assert 'ES s=set(rc_name,&rc_guid,0,0,0);' in services
assert 'else result=RC_UNCERTAIN;' in services
assert 'for(;;)__asm__ volatile("pause")' in services

# Execute exact carrier entry until its first initialization call. No UEFI
# service or ST memory is mapped. This checks its literal NULL proof argument,
# not initialization behavior or an entire recovery session.
u=Uc(UC_ARCH_X86,UC_MODE_64);base=pe.OPTIONAL_HEADER.ImageBase;size=(pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
u.mem_map(base,size);u.mem_write(base,pe.get_memory_mapped_image());u.mem_protect(base,size,UC_PROT_READ|UC_PROT_EXEC)
u.mem_map(0x500000,0x10000,UC_PROT_READ|UC_PROT_WRITE);u.reg_write(UC_X86_REG_RSP,0x50ff08)
u.mem_write(0x50ff08,struct.pack('<Q',0x600000));u.reg_write(UC_X86_REG_RCX,0xdead0000);u.reg_write(UC_X86_REG_RDX,0xdead1000)
seen=[];target=base+build['component']['symbols']['rc_initialize']
def at_call(uc,address,size,unused):
    if address==target:
        seen.append([uc.reg_read(r) for r in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]])
        uc.emu_stop()
u.hook_add(UC_HOOK_CODE,at_call)
u.emu_start(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint,base+pe.OPTIONAL_HEADER.SizeOfImage,count=1000)
assert u.reg_read(UC_X86_REG_RIP)==target and seen==[[0xdead1000,0,0,0]]

out=dict(status='PASS_FROZEN_READONLY_RECOVERY03_REVIEW_AND_LITERAL_NULL_AUTHORITY_ENTRY',release_ready=False,
    manifest=binding(mp),checked_binding_count=62,checked_bindings=checked,
    component=binding(efi),separate_TCG_LAB=binding(lab),
    independent_actual_entry=dict(executed_until='rc_initialize first instruction',system_table_unmapped=True,
        proof_pointer=0,proof_context=0,proof_epoch=0,UEFI_services_executed=False,
        limit='Initialization was not executed by this reviewer; this proves the exact entry supplies no write authority.'),
    independent_boot_media_check=dict(ISO_contains_exact_LAB_EFI=True,not_readonly_component=True,
        ISO=binding(iso),helper_source=binding(helper_path)),
    source_review=[
        'Actual standalone entry supplies NULL writer exclusion; matching SMBIOS/modules alone cannot authorize deletion.',
        'Identity uses exact W890 module shapes and full original text SHA, plus checksummed/bounded SMBIOS Type0/Type2 parsing; actual SMBIOS strings remain unobserved.',
        'Enabled 128-byte attributes-3 private record only; known-password verifier, repeated identity/exclusion check and unchanged final reread precede namespaced delete.',
        'No compare-delete atomic primitive exists in this design. Its unimplemented exclusion authority is explicitly required across final read/delete.',
        'Disabled, wrong/malformed/changed records refuse; delete status/readback ambiguity is not reported as success.',
        'UI masks input and returns without prompting when authority is missing; normal success path restores display and wipes private byte arrays.',
        'Uncertain event closure leaves the application resident in PAUSE without further UEFI calls; it requires restart instead of unsafe unload.',
        'DPAPI handoff is a local owned-QEMU-stdio transport only, validates the full alphabet before sending, and emits metadata without secrets.'
    ],
    reported_behavior=dict(actual_EFI_report=binding(D/'build/recovery_pe_tests.json'),actual_EFI_cases=54,
        actual_EFI_model='UEFI/SHA/PBKDF and writer authority are explicit models; actual compiled parser/UI/lifetime/control flow executes.',
        OVMF_report=binding(RUN/'result.json'),OVMF_assertions=28,
        OVMF_actual='SHA/KDF, NV variables, GOP, real SimpleTextInput and DPAPI-to-QMP keyboard-to-known-password deletion chain.',
        OVMF_model='Separate TCG carrier supplies inert original module and SMBIOS fixtures, plus modeled writer exclusion.',
        DPAPI_report=binding(D/'build/handoff_tests.json'),DPAPI_cases=8,
        DPAPI_scope='Actual current-user DPAPI validation; key sink modeled in 8-case suite, real keyboard transport in separate OVMF run.',
        independently_rerun_by_reviewer=False,secret_checks_attributed_to_password_agent=True),
    limits=[
        'No hardware recovery use is authorized or established by this read-only component. No BMC keyboard adapter exists.',
        'Exact runtime hardware SMBIOS Type0/Type2 strings, trusted original-boot/writer exclusion and physical controller transport remain unbound.',
        'Page-table walker assumes page-table physical pages are directly readable through their addresses in the pre-boot environment; page presence alone is not ownership/lifetime or an executable-call authorization.',
        'Protocol/table/loaded-image lifetime still depends on platform contracts; offline data fixtures do not establish those contracts on ASUS hardware.',
        'Disabled records intentionally cannot be authenticated and remain undeletable until separate ownership recovery is specified.',
        'After ambiguous event closure the user must restart; resident behavior is containment, not a usable recovery return.',
        'The LAB is executable test infrastructure with injected writer authority and must not become physical boot media or be packaged as deployable firmware.',
        'Python plaintext immutable copies are not reliably wiped; no protection against a compromised Windows account is claimed.'
    ],reviewer_decrypted_secrets=False,reviewer_network_or_device_actions=False)
(HERE/'recovery03_component_review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=out['status'],bindings=62,EFI_cases=54,OVMF_assertions=28,DPAPI_cases=8,
    sha256=sha(HERE/'recovery03_component_review.json'))))
