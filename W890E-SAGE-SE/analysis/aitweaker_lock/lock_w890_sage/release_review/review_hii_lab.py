"""Independent binding/fixture/boot-media/entry review of root's TCG HII lab.

Does not rerun the VM or call hardware/HII services. Entry rejection is replayed
locally using actual EFI instructions and deliberately unmapped system tables.
Writes only this review directory.
"""
from pathlib import Path
from collections import Counter
import hashlib, io, json, re, struct, sys, uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
BOARD = HERE.parent
ROOT = HERE.parents[3]
LAB = BOARD / 'hii_lab01'
RUN = LAB / 'runs/20261108_013828'
sys.path[:0] = [str(ROOT/'tools/pydeps'), str(ROOT/'tools/kvm-pydeps')]
import pefile
import pycdlib
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN, UC_HOOK_MEM_WRITE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_INS_CPUID, UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RAX

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(b): return hashlib.sha256(b).hexdigest()
def read(p): return json.loads(p.read_text(encoding='utf-8'))
def binding(p): return dict(path=str(p.resolve()), size=p.stat().st_size, sha256=sha(p))
def u16(b, p): return struct.unpack_from('<H', b, p)[0]
def u32(b, p): return struct.unpack_from('<I', b, p)[0]
def carray(text, name):
    m = re.search(r'\b'+re.escape(name)+r'\[\]\s*=\s*\{([^}]*)\}', text, re.S)
    assert m
    return bytes(int(s, 16) for s in re.findall(r'0x[0-9a-fA-F]+', m[1]))

def packages(b):
    assert len(b) >= 24 and u32(b, 16) == len(b)
    out = []; at = 20
    while at < len(b):
        h = u32(b, at); n = h & 0xffffff; kind = h >> 24
        assert 4 <= n <= len(b)-at
        out.append((kind, b[at:at+n]))
        at += n
        if kind == 0xdf:
            assert n == 4 and at == len(b)
            return out
    raise AssertionError('missing package-list terminator')

def string_token_range(b):
    assert u32(b, 0) >> 24 == 4 and (u32(b, 0) & 0xffffff) == len(b)
    at = u32(b, 8); token = 1; assigned = set(); block_counts = Counter()
    assert 46 < at < len(b) and b[46:52] == b'en-US\0'
    while at < len(b):
        begin = at; op = b[at]; at += 1; block_counts[op] += 1
        if op == 0:
            assert at == len(b)
            return dict(max_assigned=max(assigned), next_token=token, strings=len(assigned),
                        block_counts={hex(k):v for k,v in block_counts.items()})
        if op in (0x14, 0x15, 0x16, 0x17):
            if op in (0x15, 0x17): at += 1
            count = u16(b, at) if op in (0x16, 0x17) else 1
            if op in (0x16, 0x17): at += 2
            for _ in range(count):
                while at + 2 <= len(b) and b[at:at+2] != b'\0\0': at += 2
                assert at + 2 <= len(b); at += 2
                assigned.add(token); token += 1
        elif op == 0x20:
            assert u16(b, at) in assigned; at += 2
            assigned.add(token); token += 1
        elif op in (0x21, 0x22):
            width = 2 if op == 0x21 else 1
            assert at+width <= len(b)
            token += int.from_bytes(b[at:at+width], 'little'); at += width
        elif op in (0x30, 0x31, 0x32, 0x40):
            width = {0x30:1, 0x31:2, 0x32:4, 0x40:2}[op]
            n = int.from_bytes(b[begin+2:begin+2+width], 'little')
            assert 2+width <= n <= len(b)-begin; at = begin+n
        else:
            raise AssertionError(f'unhandled actual string block {op:#x}')
        assert token <= 0x10000 and at <= len(b)
    raise AssertionError('unterminated string block stream')

def fat16_file(disk, names):
    bps = u16(disk, 11); spc = disk[13]; reserved = u16(disk, 14)
    fats = disk[16]; root_entries = u16(disk, 17); fat_sectors = u16(disk, 22)
    assert bps == 512 and spc and spc & (spc-1) == 0 and fats in (1,2)
    root_at = (reserved+fats*fat_sectors)*bps
    root_size = ((root_entries*32+bps-1)//bps)*bps
    data_at = root_at+root_size; fat_at = reserved*bps; cluster_bytes = spc*bps
    def chain(cluster):
        result = bytearray(); seen = set()
        while cluster < 0xfff8:
            assert 2 <= cluster < 0xfff0 and cluster not in seen
            seen.add(cluster); assert len(seen) < 65536
            offset = data_at+(cluster-2)*cluster_bytes
            assert offset+cluster_bytes <= len(disk)
            result += disk[offset:offset+cluster_bytes]
            cluster = u16(disk, fat_at+cluster*2)
        return bytes(result)
    directory = disk[root_at:root_at+root_size]
    for i, name in enumerate(names):
        found = []
        for offset in range(0, len(directory), 32):
            ent = directory[offset:offset+32]
            if ent[0] == 0: break
            if ent[0] == 0xe5 or ent[11] == 0x0f: continue
            if ent[:11] == name: found.append(ent)
        assert len(found) == 1
        ent = found[0]; payload = chain(u16(ent, 26))
        if i == len(names)-1:
            assert not ent[11] & 0x10 and u32(ent, 28) <= len(payload)
            return payload[:u32(ent, 28)]
        assert ent[11] & 0x10; directory = payload
    raise AssertionError('empty FAT path')

result = read(RUN/'result.json'); checked = []
assert result['status'] == 'PASS_REAL_OVMF_HII_PUBLICATION_UPDATE_ROLLBACK_REMOVAL'
for name, item in result['source_bindings'].items():
    p = Path(name); assert p.resolve().is_relative_to(ROOT.resolve())
    assert p.stat().st_size == item['bytes'] and sha(p) == item['sha256']
    checked.append(binding(p))
assert read(RUN/'inputs.json') == result['source_bindings'] and len(checked) == 12
efi = RUN/'W890-HII-LAB01.TCG-ONLY.efi'; iso = RUN/'W890-HII-LAB01.TCG-ONLY.iso'
assert sha(efi) == result['efi_sha256'] == '75b4afb1361575332f6042a05d4e4d8fa9e4860bae30bd49574579cad8d7bf0f'
assert sha(iso) == result['iso_sha256_before'] == result['iso_sha256_after']
assert sha(ROOT/'tools/qemu-11.1.0/share/edk2-x86_64-code.fd') == result['ovmf_sha256']
debug = (RUN/'debug.log').read_text(encoding='ascii')
assert sha(RUN/'debug.log') == result['debug_sha256'] and result['exit_code'] == 33
lab_log = debug[debug.index('W890_HII_LAB01_BEGIN\n'):]
assert lab_log.endswith('W890_HII_LAB01_PASS\n') and 'FAIL ' not in lab_log
assert len(re.findall(r'^PASS ', lab_log, re.M)) == result['checks'] == 76
counts = Counter(re.findall(r'^PASS (.*)$', lab_log, re.M))
assert counts['real new string gets a noncolliding token'] == counts['new string readback matches'] == 6
assert counts['new tokens unique'] == 15
assert counts['allocated prompt remains after update'] == 6
assert counts['allocate bounded private buffer'] == counts['free private buffer'] == 7

fixtures = (RUN/'fixtures.h').read_text(encoding='ascii')
original = carray(fixtures, 'original_package'); forms = carray(fixtures, 'original_forms')
assert digest(forms) == result['original_forms_sha256'] == '0111abd4e9914a32b865fc95af15990687a9d05f984df533c30e028e38cbba2f'
assert forms == (BOARD/'password/official_forms_0603.pack').read_bytes()
items = packages(original); assert [kind for kind,_ in items] == [2,4,0xdf]
assert items[0][1] == forms
setup = next(Path(p) for p,d in result['source_bindings'].items() if d['sha256'] == 'c1cf9d755c2ea043d44f19fdf4009cf8b12b03f85e8939034de19ee18251b72e')
english = items[1][1]; setup_raw = setup.read_bytes()
assert setup_raw.count(english) == 1
english_at = setup_raw.find(english)
tokens = string_token_range(english)
declared = int(re.search(r'#define ORIGINAL_MAX_STRING (\d+)', fixtures)[1])
assert declared == tokens['max_assigned']
lab_list_guid = str(uuid.UUID(bytes_le=original[:16]))
assert lab_list_guid == '15b535e2-608f-493e-bfea-d3aa1ce7b50c'
formsets = []; at = 4
while at < len(forms):
    n = forms[at+1] & 0x7f; assert n >= 2 and at+n <= len(forms)
    if forms[at] == 0x0e:
        assert n >= 18; formsets.append(str(uuid.UUID(bytes_le=forms[at+2:at+18])))
    at += n
assert at == len(forms) and formsets and lab_list_guid not in formsets
pe = pefile.PE(str(efi))
assert pe.verify_checksum() and pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Subsystem == 10
assert not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
assert efi.read_bytes().count(original) == 1
cd = pycdlib.PyCdlib(); cd.open(str(iso)); embedded = io.BytesIO()
cd.get_file_from_iso_fp(embedded, iso_path='/EFIBOOT.IMG;1'); cd.close()
boot_bytes = embedded.getvalue(); assert boot_bytes == (RUN/'boot.img').read_bytes()
assert fat16_file(boot_bytes, [b'EFI        ', b'BOOT       ', b'BOOTX64 EFI']) == efi.read_bytes()

source = (LAB/'lab.c').read_text()
entry = source[source.index('ES EA efi_main('):]
assert entry.index('if(!tcg())return ERR(3);') < entry.index('st=system;') < entry.index('locate_protocol')
assert '->rt' not in source and 'send_form' not in source and 'handle_protocol' not in source
source_scopes = [
    'TCG check precedes assignment/use of the system table and all HII or I/O services.',
    'Only fresh lab-owned package handles are passed to update/remove; the lab does not locate an existing ASUS Setup HII handle.',
    'Management package driver association is checked against the lab image handle; original-byte package uses a separate lab package-list GUID.',
    'Bounded private allocations, exported package lengths, exact forms bytes, strings and non-form packages are checked.',
    'Actual w890_security_insert receives six tokens allocated by real HII String services; exported changed forms are byte-exact.',
    'Success path restores original forms, preserves post-NewString non-form packages, frees private allocations and removes both lab handles.',
    'Check failure exits the VM through debug I/O instead of implementing a production error-recovery/unload path.'
]
own_guard = []
for name, cpuid in [('non_hypervisor', (0,0,0,0)), ('non_TCG_hypervisor', (0x40000001,0x7263694d,0x666f736f,0x76482074))]:
    u = Uc(UC_ARCH_X86, UC_MODE_64); base = pe.OPTIONAL_HEADER.ImageBase
    size = (pe.OPTIONAL_HEADER.SizeOfImage+4095)&~4095
    u.mem_map(base, size); u.mem_write(base, pe.get_memory_mapped_image())
    before = bytes(u.mem_read(base,size)); u.mem_protect(base,size,UC_PROT_READ|UC_PROT_EXEC)
    u.mem_map(0x500000,0x10000,UC_PROT_READ|UC_PROT_WRITE)
    u.mem_map(0x600000,0x1000,UC_PROT_READ|UC_PROT_EXEC)
    u.reg_write(UC_X86_REG_RSP,0x50ff08); u.mem_write(0x50ff08,struct.pack('<Q',0x600000))
    u.reg_write(UC_X86_REG_RCX,0xdead0000); u.reg_write(UC_X86_REG_RDX,0xdead1000)
    calls=[]; writes=[]
    def cpu(uc,unused):
        calls.append(uc.reg_read(UC_X86_REG_EAX))
        for reg,val in zip([UC_X86_REG_EAX,UC_X86_REG_EBX,UC_X86_REG_ECX,UC_X86_REG_EDX], cpuid): uc.reg_write(reg,val)
        return 1
    u.hook_add(UC_HOOK_INSN,cpu,None,1,0,UC_X86_INS_CPUID)
    u.hook_add(UC_HOOK_MEM_WRITE,lambda uc,a,address,n,value,user:writes.append((address,n)))
    u.emu_start(base+pe.OPTIONAL_HEADER.AddressOfEntryPoint,0x600000,count=1000)
    assert u.reg_read(UC_X86_REG_RIP)==0x600000 and u.reg_read(UC_X86_REG_RAX)==0x8000000000000003
    assert calls==[0x40000000] and all(0x500000<=a and a+n<=0x510000 for a,n in writes)
    assert bytes(u.mem_read(base,size))==before
    own_guard.append(dict(case=name,passed=True,actual_EFI_entry_executed=True,
        image_RX_and_unchanged=True,system_table_unmapped=True,return_status='EFI_UNSUPPORTED'))
root_guard = read(RUN/'entry_guard_tests.json')
assert root_guard['efi_sha256'] == sha(efi) and root_guard['passed'] and len(root_guard['cases']) == 2
assert all(c['passed'] and not c['firmware_service_access'] and c['image_memory_unchanged'] for c in root_guard['cases'])

out = dict(status='PASS_BOUND_OVMF_HII_LAB_REVIEW_AND_INDEPENDENT_ENTRY_REPLAY', release_ready=False,
    source_bindings=checked, source_binding_count=len(checked), reviewed_source_scope=source_scopes,
    artifact_bindings=[binding(p) for p in [efi,iso,RUN/'result.json',RUN/'inputs.json',RUN/'build_commands.json',RUN/'qemu_command.json',RUN/'debug.log',RUN/'entry_guard_tests.json',LAB/'verify_guard.py']],
    actual_VM_result=dict(executed_by='root',independently_rerun_by_reviewer=False,
        assertions=76,allocated_token_checks=6,pairwise_unique_assertions=15,
        allocations=7,frees=7,successful_exit_code=33,debug_log_hash_verified=True,
        isolated_original_package_list_guid=lab_list_guid,original_formset_guids_retained=formsets,
        real_services=['HiiDatabase NewPackageList/GetDriverHandle/ExportPackageLists/UpdatePackageList/RemovePackageList','HiiString NewString/GetString']),
    independent_fixture_check=dict(forms_sha256=digest(forms),forms_bytes=len(forms),
        english_strings_sha256=digest(english),english_bytes=len(english),setup_offset=hex(english_at),
        english_exact_original_match=True,token_range=tokens,declared_original_max=declared,
        lab_package_bytes=len(original),lab_package_sha256=digest(original),
        package_embedded_in_actual_EFI=True,ISO_boot_image_and_FAT_EFI_exact=True),
    independent_entry_replay=own_guard,
    limits=[
        '76 are assertions, including allocation/free and pairwise-token comparisons; not 76 distinct functional scenarios.',
        'Real OVMF public HII services and original W890 data were exercised; ASUS SendForm/rendering, native owner/ConfigAccess dispatch and write interception were not.',
        'Original package-list GUID is isolated, while original FormSet GUIDs remain in its forms. No hardware-safe duplicate-FormSet publication is claimed.',
        'Rollback restores original forms only. Newly allocated strings remain during that comparison and disappear when the isolated package list is removed.',
        'No HII error injection, asynchronous notification/reentrancy, language expansion, unload-after-error or hardware entry tests are established by this positive run.',
        'TCG CPUID is an accidental-execution guard, not authorization or a universal hardware-safety boundary.',
        'The lab calls debug-exit/halts on any check failure; it is not a deployable driver or a firmware candidate.'
    ], reviewer_network_or_device_actions=False)
(HERE/'hii_lab_review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(status=out['status'],sources=len(checked),assertions=76,
    original_max_string=declared,entry_cases=len(own_guard),sha256=sha(HERE/'hii_lab_review.json'))))
