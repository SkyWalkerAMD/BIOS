"""Exact-baseline, in-memory AMITSE PE composition.

This module does not write a firmware candidate. It preserves original section
RVAs and all original file bytes except explicitly reviewed text overlays and
PE metadata. A freestanding extension retains its internal relative layout;
all DIR64 locations are rebased and included in the resulting relocation table.
Functional authority, firmware loading and hardware boot are separate checks.
"""
from pathlib import Path
from collections import defaultdict
import hashlib, json, struct, sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
ROOT = BASE.parents[2]
sys.path.insert(0, str(ROOT / 'tools/pydeps'))
import pefile
import capstone

ORIGINAL_SHA = '43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
DIR64 = 10

def sha(b): return hashlib.sha256(b).hexdigest()
def align(n, a): return (n + a - 1) & ~(a - 1)
def need(ok, message):
    if not ok: raise ValueError(message)
def u32(b, at): return struct.unpack_from('<I', b, at)[0]
def u64(b, at): return struct.unpack_from('<Q', b, at)[0]

def baseline():
    item = json.loads((BASE/'password/profile_0603.json').read_text())['sources']['AMITSE']
    raw = (ROOT/item['path']).read_bytes()
    need(sha(raw) == ORIGINAL_SHA == item['sha256'], 'AMITSE baseline identity')
    return raw

def relocations(pe):
    """Only the reviewed x64 DIR64/ABSOLUTE format is admitted."""
    out = []
    for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
        need(block.struct.SizeOfBlock >= 8 and not block.struct.SizeOfBlock % 4,
             'base relocation block alignment')
        for item in block.entries:
            need(item.type in (0, DIR64), 'unsupported relocation type')
            if item.type == DIR64:
                need(item.rva + 8 <= pe.OPTIONAL_HEADER.SizeOfImage, 'relocation bounds')
                out.append(item.rva)
    need(len(out) == len(set(out)), 'duplicate relocation')
    return sorted(out)

def relocation_bytes(locations):
    blocks = defaultdict(list)
    for rva in sorted(locations): blocks[rva & ~4095].append((DIR64 << 12) | (rva & 4095))
    out = bytearray()
    for page, values in sorted(blocks.items()):
        if len(values) % 2: values.append(0)
        out += struct.pack('<II', page, 8 + 2 * len(values))
        out += struct.pack('<' + 'H' * len(values), *values)
    return bytes(out)

def exports(pe):
    result = {}
    for symbol in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []):
        if symbol.name is None: continue
        need(not symbol.forwarder, 'forwarded export is not freestanding')
        name = symbol.name.decode('ascii')
        need(name not in result, 'duplicate export name')
        need(0 < symbol.address < pe.OPTIONAL_HEADER.SizeOfImage, 'export bounds')
        result[name] = symbol.address
    return result

def section_at(pe, rva, size=1):
    found = [s for s in pe.sections if s.VirtualAddress <= rva and
             rva + size <= s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)]
    need(len(found) == 1, 'RVA must have one section owner')
    return found[0]

def raw_offset(pe, rva, size=1):
    s = section_at(pe, rva, size)
    need(rva + size <= s.VirtualAddress + s.SizeOfRawData, 'RVA has no initialized file bytes')
    return s.PointerToRawData + rva - s.VirtualAddress

def mapped(pe):
    data = pe.get_memory_mapped_image()
    need(len(data) <= pe.OPTIONAL_HEADER.SizeOfImage, 'mapped image length')
    return data.ljust(pe.OPTIONAL_HEADER.SizeOfImage, b'\0')

def decode_window(raw, rva, trampoline, approved=()):
    d = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); d.detail = True
    rows = list(d.disasm(raw, rva))
    need(sum(x.size for x in rows) == len(raw), 'patch window must contain complete instructions')
    seen=[]
    if trampoline:
        for x in rows:
            need(not any(x.group(g) for g in [capstone.CS_GRP_JUMP,
                                            capstone.CS_GRP_RET, capstone.CS_GRP_INT]),
                 'trampoline window has control transfer')
            if x.group(capstone.CS_GRP_CALL):
                need(x.bytes[0]==0xe8 and x.size==5,'only exact rel32 CALL may relocate')
                seen.append({'rva':x.address,'target':x.address+5+int.from_bytes(x.bytes[1:],'little',signed=True),'kind':'call'})
            for o in x.operands:
                if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP:
                    need(x.disp_size==4,'RIP-relative displacement width')
                    seen.append({'rva':x.address,'target':x.address+x.size+o.mem.disp,'kind':'rip'})
    need(seen==list(approved),'PC-relative instructions require exact reviewed target list')
    return [{'rva': x.address, 'bytes': x.bytes.hex(), 'mnemonic': x.mnemonic,
             'operands': x.op_str} for x in rows]

def rel32(op, source, target):
    delta = target - source - 5
    need(-(1 << 31) <= delta < (1 << 31), 'relative branch out of range')
    return bytes([op]) + struct.pack('<i', delta)

def relocate_window(raw, source, destination, approved):
    decode_window(raw,source,True,approved)
    d=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);d.detail=True
    result=bytearray(raw)
    by_rva={p['rva']:p for p in approved};need(len(by_rva)==len(approved),'one relocation operand per instruction')
    for ins in d.disasm(raw,source):
        if ins.address not in by_rva:continue
        r=by_rva[ins.address];off=ins.address-source;new_pc=destination+off
        if r['kind']=='call':result[off:off+ins.size]=rel32(0xe8,new_pc,r['target'])
        else:
            delta=r['target']-new_pc-ins.size;need(-(1<<31)<=delta<(1<<31),'RIP target out of range')
            struct.pack_into('<i',result,off+ins.disp_offset,delta)
    return bytes(result)

def compose(extension, expected_sha, entry_export, patches=(), pointer_patches=(), internal_symbols=()):
    """Return (merged PE bytes, evidence), never emit CAP/ROM or run entry code.

    patches: {rva, original_hex, export, mode:call|jmp, trampoline?:name}.
    Each window must match the pinned original and contain whole instructions.
    Trampolines admit straight-line instructions, plus specifically listed
    RIP-relative operands and direct calls with independently reviewed targets.
    The entry export must have EFI's (ImageHandle, SystemTable) entry ABI.
    """
    original = baseline(); need(sha(extension) == expected_sha, 'extension SHA256 mismatch')
    old = pefile.PE(data=original); ext = pefile.PE(data=extension)
    for p in (old, ext):
        need(p.FILE_HEADER.Machine == 0x8664 and p.OPTIONAL_HEADER.Magic == 0x20b, 'x64 PE32+')
        need(not p.FILE_HEADER.Characteristics & 1, 'relocations stripped')
        need(p.OPTIONAL_HEADER.SectionAlignment == 4096 and p.OPTIONAL_HEADER.FileAlignment == 512,
             'reviewed PE alignments')
        need(len(p.sections) <= 8, 'section bound')
    need(old.OPTIONAL_HEADER.ImageBase == 0 and old.OPTIONAL_HEADER.SizeOfImage == 0xde000,
         'original image layout')
    need(old.OPTIONAL_HEADER.AddressOfEntryPoint == 0x6480, 'original entry')
    # Export metadata is read offline; the extension is not an independently loaded DLL.
    for i, d in enumerate(ext.OPTIONAL_HEADER.DATA_DIRECTORY):
        if i not in (0, 5): need(not d.VirtualAddress and not d.Size, f'unsupported extension directory {i}')
    need(ext.OPTIONAL_HEADER.AddressOfEntryPoint == 0, 'extension requires /noentry')
    need(0 < ext.OPTIONAL_HEADER.SizeOfImage <= 0x2000000, 'bounded extension image')
    ex = exports(ext); need(entry_export in ex, 'entry export absent')
    need(section_at(ext, ex[entry_export]).Characteristics & 0x20000000, 'entry must execute')
    original_relocs = relocations(old); extra_relocs = relocations(ext)
    need(original_relocs and extra_relocs, 'both images require nonempty reviewed relocations')
    original_extension_image=mapped(ext);consumer_rows=[]
    for symbol in internal_symbols:
        name=symbol['name'];ret=symbol['rva'];ins=symbol['instruction_rva'];raw=bytes.fromhex(symbol['instruction_hex'])
        need(name not in ex and len(name.encode())<40 and name.startswith(('i05_effect_','i05_request_','i05_manage_','i05_scope_')),
             'reviewed internal symbol namespace')
        need(symbol['kind']in(1,2,3,4),'reviewed consumer kind')
        need(ret==ins+len(raw) and 16<=ret<ext.OPTIONAL_HEADER.SizeOfImage-16,'consumer return range')
        need(original_extension_image[ins:ret]==raw and original_extension_image[ret-16:ret+16].hex()==symbol['window_hex'],
             'consumer instruction/window binding')
        need(section_at(ext,ins,len(raw)).Characteristics&0x20000000,'consumer must execute')
        target_name=symbol['target_export'];need(target_name in ex,'consumer target export required')
        target=ex[target_name]+symbol.get('target_offset',0)
        if len(raw)==5 and raw[0]==0xe8:
            need(ret+int.from_bytes(raw[1:],'little',signed=True)==target,'consumer E8 target')
            need(target_name=='no_scope_enter' and not symbol.get('target_offset',0) and symbol['kind']in(1,4),'reviewed direct authority target')
        elif len(raw)==6 and raw[:2]==b'\xff\x15':
            need(ret+int.from_bytes(raw[2:],'little',signed=True)==target,'consumer RIP-indirect slot')
            need(target_name=='w890_provider' and symbol.get('target_offset')==40 and symbol['kind']==3,'reviewed request slot')
        else:raise ValueError('unsupported internal authority call encoding')
        ex[name]=ret;consumer_rows.append(dict(symbol))
    ext_start = align(old.OPTIONAL_HEADER.SizeOfImage, 4096)
    ex = {k: ext_start + v for k, v in ex.items()}
    ext_image = mapped(ext); buf = bytearray(original)
    new_sections = []
    original_sections = [{'name': s.Name.rstrip(b'\0').decode('ascii'), 'rva': s.VirtualAddress,
        'virtual_bytes': s.Misc_VirtualSize, 'raw_bytes': s.SizeOfRawData,
        'file_offset': s.PointerToRawData, 'characteristics': s.Characteristics} for s in old.sections]

    def append_section(name, rva, vsize, data, flags):
        need(len(name) <= 8 and 0 <= len(data) <= max(vsize, len(data)), 'section parameters')
        need(not (flags & 0x20000000 and flags & 0x80000000), 'extension section must not be writable executable')
        ptr = align(len(buf), 512) if data else 0
        if data:
            buf.extend(b'\0' * (ptr-len(buf))); buf.extend(data)
            buf.extend(b'\0' * (align(len(buf),512)-len(buf)))
        raw_size = align(len(data),512) if data else 0
        new_sections.append({'name': name, 'rva': rva, 'virtual_bytes': vsize,
            'raw_bytes': raw_size, 'file_offset': ptr, 'characteristics': flags})

    ranges = []
    for i, s in enumerate(ext.sections):
        need(s.VirtualAddress >= ext.OPTIONAL_HEADER.SizeOfHeaders and not s.VirtualAddress % 4096,
             'extension section RVA/alignment')
        hi = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        need(hi <= ext.OPTIONAL_HEADER.SizeOfImage, 'extension section image bounds')
        need(all(hi <= lo or s.VirtualAddress >= end for lo,end in ranges), 'extension section overlap')
        ranges.append((s.VirtualAddress, hi))
        data = bytearray(extension[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData])
        need(len(data) == s.SizeOfRawData, 'extension raw bounds')
        for rva in extra_relocs:
            if s.VirtualAddress <= rva < hi:
                off = rva - s.VirtualAddress; need(off+8 <= len(data), 'relocation needs initialized section')
                value = u64(data,off); target = value - ext.OPTIONAL_HEADER.ImageBase
                need(0 <= target < ext.OPTIONAL_HEADER.SizeOfImage, 'extension pointer outside its image')
                section_at(ext,target)
                struct.pack_into('<Q',data,off,ext_start+target)
        append_section(f'.lk{i}', ext_start+s.VirtualAddress, s.Misc_VirtualSize, bytes(data),s.Characteristics)

    current_end = align(ext_start+ext.OPTIONAL_HEADER.SizeOfImage,4096)
    overlays = []; trampoline_data = bytearray(); used = []; trampoline_map = {}; data_overlays=[]
    for pointer in pointer_patches:
        rva=pointer['rva'];original_value=pointer['original_value'];name=pointer['export']
        need(rva%8==0 and rva in original_relocs,'pointer patch must be an existing aligned DIR64')
        owner=section_at(old,rva,8);need(owner.Name==b'.data\0\0\0' and owner.Characteristics&0x80000000,'reviewed original data pointer')
        off=raw_offset(old,rva,8);need(u64(original,off)==original_value,'original data target mismatch')
        need(section_at(old,original_value).Characteristics&0x20000000,'original pointer must target original code')
        need(name in ex and section_at(ext,ex[name]-ext_start).Characteristics&0x20000000,'new pointer must target extension code')
        need(not any(p['rva']==rva for p in data_overlays),'duplicate data pointer patch')
        struct.pack_into('<Q',buf,off,ex[name])
        data_overlays.append({'rva':rva,'original_value':original_value,'installed_value':ex[name],'export':name,'existing_DIR64_preserved':True})
    for patch in patches:
        rva = patch['rva']; raw = bytes.fromhex(patch['original_hex']); mode = patch['mode']
        need(mode in ('call','jmp') and 5 <= len(raw) <= 32, 'patch mode/length')
        need(mode != 'call' or len(raw) == 5, 'call bridge must replace exactly five bytes')
        sec = section_at(old,rva,len(raw)); need(sec.Name == b'.text\0\0\0', 'only original text can be patched')
        off = raw_offset(old,rva,len(raw)); need(original[off:off+len(raw)] == raw, 'original window mismatch')
        need(all(rva+len(raw) <= lo or rva >= hi for lo,hi in used), 'overlapping patch windows')
        need(all(r+8 <= rva or r >= rva+len(raw) for r in original_relocs), 'patch overlaps original relocation')
        used.append((rva,rva+len(raw))); need(patch['export'] in ex, 'hook export absent')
        need(section_at(ext,ex[patch['export']]-ext_start).Characteristics & 0x20000000,'hook must execute')
        instructions = decode_window(raw,rva,bool(patch.get('trampoline')),patch.get('pc_relative_targets',[]))
        installed = rel32(0xe8 if mode == 'call' else 0xe9,rva,ex[patch['export']])+b'\x90'*(len(raw)-5)
        buf[off:off+len(raw)] = installed
        row = {'rva':rva,'bytes':len(raw),'original_hex':raw.hex(),'installed_hex':installed.hex(),
               'export':patch['export'],'target_rva':ex[patch['export']],'mode':mode,'instructions':instructions}
        if patch.get('trampoline'):
            name=patch['trampoline']; need(mode=='jmp' and name not in trampoline_map,'trampoline name/mode')
            trampoline_data.extend(b'\x90'*(align(len(trampoline_data),16)-len(trampoline_data)))
            at=current_end+len(trampoline_data); trampoline_map[name]=at
            relocated=relocate_window(raw,rva,at,patch.get('pc_relative_targets',[]))
            trampoline_data.extend(relocated); trampoline_data.extend(rel32(0xe9,at+len(raw),rva+len(raw)))
            row['trampoline']={'name':name,'rva':at,'resume_rva':rva+len(raw),'bytes':len(raw)+5}
            row['trampoline']['relocated_hex']=relocated.hex()
            row['trampoline']['pc_relative_targets']=patch.get('pc_relative_targets',[])
        overlays.append(row)
    if trampoline_data:
        append_section('.lktramp',current_end,len(trampoline_data),bytes(trampoline_data),0x60000020)
        current_end=align(current_end+len(trampoline_data),4096)
    combined_relocs=original_relocs+[ext_start+r for r in extra_relocs]
    relocation_data=relocation_bytes(combined_relocs)
    relocation_rva=current_end
    append_section('.lkreloc',relocation_rva,len(relocation_data),relocation_data,0x42000040)
    image_size=align(relocation_rva+len(relocation_data),4096)
    nt=old.DOS_HEADER.e_lfanew; optional=nt+24
    section_table=optional+old.FILE_HEADER.SizeOfOptionalHeader
    count=len(old.sections)+len(new_sections)
    headers=old.OPTIONAL_HEADER.SizeOfHeaders
    header_start=section_table+len(old.sections)*40; header_end=section_table+count*40
    need(header_end<=headers and original[header_start:header_end]==b'\0'*(header_end-header_start),
         'new sections do not fit zero header space')
    for i,s in enumerate(new_sections):
        at=header_start+40*i
        struct.pack_into('<8sIIIIIIHHI',buf,at,s['name'].encode().ljust(8,b'\0'),s['virtual_bytes'],
            s['rva'],s['raw_bytes'],s['file_offset'],0,0,0,0,s['characteristics'])
    struct.pack_into('<H',buf,nt+6,count)
    struct.pack_into('<I',buf,optional+16,ex[entry_export])
    struct.pack_into('<I',buf,optional+56,image_size)
    struct.pack_into('<II',buf,optional+112+5*8,relocation_rva,len(relocation_data))
    for field,flag in [(4,0x20),(8,0x40),(12,0x80)]:
        old_value=u32(original,optional+field)
        added=sum((s['virtual_bytes'] if flag==0x80 else s['raw_bytes'])
                  for s in new_sections if s['characteristics']&flag)
        struct.pack_into('<I',buf,optional+field,old_value+added)
    struct.pack_into('<I',buf,optional+64,0)
    merged=pefile.PE(data=bytes(buf)); struct.pack_into('<I',buf,optional+64,merged.generate_checksum())
    merged=pefile.PE(data=bytes(buf))
    need(merged.OPTIONAL_HEADER.CheckSum==merged.generate_checksum(),'PE checksum')
    need(relocations(merged)==sorted(combined_relocs),'combined relocations')
    for index,s in enumerate(old.sections):
        need(s.__pack__()==merged.sections[index].__pack__(),'original section header changed')
        expected=bytearray(original[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData])
        for p in overlays:
            if s.VirtualAddress <= p['rva'] < s.VirtualAddress+s.SizeOfRawData:
                at=p['rva']-s.VirtualAddress; expected[at:at+p['bytes']]=bytes.fromhex(p['installed_hex'])
        for p in data_overlays:
            if s.VirtualAddress<=p['rva']<s.VirtualAddress+s.SizeOfRawData:
                struct.pack_into('<Q',expected,p['rva']-s.VirtualAddress,p['installed_value'])
        need(bytes(expected)==bytes(buf[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]),
             'unreviewed change in original section')
    old_text=next(s for s in old.sections if s.Name==b'.text\0\0\0')
    report={'status':'COMPOSED_IN_MEMORY_REQUIRES_FUNCTIONAL_AND_PLATFORM_VALIDATION',
        'original_sha256':sha(original),'extension_sha256':sha(extension),'merged_sha256':sha(buf),
        'merged_file_bytes':len(buf),'original_image_size':old.OPTIONAL_HEADER.SizeOfImage,
        'image_size':image_size,'extension_rva':ext_start,'extension_image_size':ext.OPTIONAL_HEADER.SizeOfImage,
        'original_entry_rva':0x6480,'entry_export':entry_export,'entry_rva':ex[entry_export],
        'original_sections':original_sections,'added_sections':new_sections,'exports':ex,
        'original_text_sha256':sha(original[old_text.PointerToRawData:old_text.PointerToRawData+old_text.Misc_VirtualSize]),
        'patches':overlays,'pointer_patches':data_overlays,'internal_consumers':consumer_rows,'trampolines':trampoline_map,'original_relocation_count':len(original_relocs),
        'extension_relocation_count':len(extra_relocs),'relocation_rva':relocation_rva,
        'original_sections_and_rvas_preserved_except_exact_overlays':True,
        'release_ready':False,'saved_firmware_candidate':False}
    return bytes(buf),report
