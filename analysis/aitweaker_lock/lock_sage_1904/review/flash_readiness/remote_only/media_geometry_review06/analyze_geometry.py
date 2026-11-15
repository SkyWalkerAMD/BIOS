"""Bounded offline geometry/caching analysis of pinned official ARM bytes."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BASE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
spec=importlib.util.spec_from_file_location('geometry_elf',BASE/'component_backend_review/build_component_evidence.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM
Elf32=mod.Elf32
sha=lambda b:hashlib.sha256(b).hexdigest()
PATTERNS=[0x40000,0x40001,0x10000400,0x10000000,0x80002]
def main():
    kernel=(BASE/'media_geometry_review03/kernel_uncompressed.bin').read_bytes()
    assert sha(kernel)=='bd66e8480131f0336c7641c700205ecd8d48a1aad5ee8101c9eb16ebf4708197'
    symbols=json.loads((BASE/'media_geometry_review03/kernel_symbols.json').read_text())['symbols']
    addresses=sorted(set(int(s['address'],16) for s in symbols));names={int(s['address'],16):s['name'] for s in symbols}
    md=Cs(CS_ARCH_ARM,CS_MODE_ARM);md.detail=True;md.skipdata=True
    outdir=HERE/'disassembly';outdir.mkdir(exist_ok=True)
    entries=[]; selected=[]
    # All named NBD/fsg functions, not arbitrary binary words, are surveyed.
    for sym in symbols:
        if not re.match(r'^(nbd_|fsg_)',sym['name']) or sym['type'].lower()!='t':continue
        start=int(sym['address'],16);end=addresses[addresses.index(start)+1]
        data=kernel[start-0x80008000:end-0x80008000]
        instructions=list(md.disasm(data,start));hits=[]
        for i in instructions:
            if i.id and any(o.type==ARM_OP_IMM and o.imm in PATTERNS for o in i.operands):
                hits.append({'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
        selected.append({'name':sym['name'],'start':hex(start),'end':hex(end),'sha256':sha(data),'constant_hits':hits})
        if sym['name'] in ['fsg_lun_open','fsg_lun_close','fsg_store_file','nbd_alloc_config','nbd_size_update','nbd_ioctl']:
            lines=[]
            for i in instructions:
                tail=''
                if i.mnemonic in ('bl','b','blx') and i.op_str.startswith('#'):
                    target=int(i.op_str[1:],0)
                    if target in names:tail=' ; '+names[target]
                lines.append(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}{tail}')
            (outdir/(sym['name']+'.txt')).write_text('\n'.join(lines)+'\n',encoding='utf8')
    sources={}
    for name in ['hdserverapp','libnbd.so.13.4.3','libusbgadget.so.13.31.13','libmediaredir.so.13.9.5']:
        dirname='bin' if name=='hdserverapp' else 'lib'
        path=HERE/'official_inputs/5308416/usr/local'/dirname/name
        e=Elf32(path);t=e.byname['.text'];data=e.data[t['offset']:t['offset']+t['size']]
        hits=[]
        for i in md.disasm(data,t['va']):
            if i.id and any(o.type==ARM_OP_IMM and o.imm in PATTERNS for o in i.operands):
                hits.append({'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
        rawhits={hex(n):[hex(m.start()) for m in re.finditer(re.escape(struct.pack('<I',n)),e.data)] for n in PATTERNS}
        sources[name]={'path':str(path.relative_to(HERE)),'sha256':sha(e.data),'text_start':hex(t['va']),'text_bytes':t['size'],
                       'immediate_hits':hits,'untyped_word_hits_not_interpreted_as_code_or_geometry':rawhits,
                       'exact_observed_RC10_bytes_offsets':[hex(m.start()) for m in re.finditer(bytes.fromhex('0004000000000400'),e.data)]}
        if name=='hdserverapp':
            ranges=[(0x12e68,0x130a4,'hd_capacity_dispatch'),(0x17dec,0x18054,'hdisk_start')]
            for start,end,label in ranges:
                off=e.offset(start,end-start);assert off is not None
                lines=[]
                for i in md.disasm(e.data[off:off+end-start],start):
                    tail=''
                    if i.mnemonic in ('bl','blx','b') and i.op_str.startswith('#'):
                        target=int(i.op_str[1:],0)
                        if target in e.names:tail=' ; '+e.names[target]
                    m=re.match(r'[^,]+, \[pc, #(\-?0x[0-9a-f]+|\-?\d+)\]',i.op_str)
                    if i.mnemonic.startswith('ldr') and m:
                        tail+=' ; '+json.dumps(e.literal(i.address+8+int(m.group(1),0)))
                    lines.append(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}{tail}')
                (outdir/(label+'.txt')).write_text('\n'.join(lines)+'\n',encoding='utf8')
    pool=json.loads((BASE/'media_attach_review02/hdserver_decompile/literal_pool.json').read_text())
    literals=[e for e in pool['entries'] if e['function_file'].startswith('00017dec')]
    capacity=kernel[0x8073743c-0x80008000:0x80737484-0x80008000]
    (outdir/'fsg_read_capacity_fragment.txt').write_text('\n'.join(f'{i.address:08x} {i.bytes.hex()} {i.mnemonic} {i.op_str}' for i in md.disasm(capacity,0x8073743c))+'\n',encoding='utf8')
    report={'kernel_sha256':sha(kernel),'constant_values_surveyed':[hex(n) for n in PATTERNS],
            'kernel_named_function_count':len(selected),'kernel_named_functions':selected,'userspace_sources':sources,
            'hdisk_start_literals':literals,
            'constant_search_limit':'Named nbd_/fsg_ original ARM functions and four shipped userspace .text sections, plus untyped raw-word search. Absence here is not proof no runtime path can create the geometry.',
            'proven_dataflow':[
              'hdserver 0x12E68 reads big-endian last LBA at packet+61, adds one modulo uint32, and stores uint64(totalBlocks) at state+0x20. Packet+65 is stored as uint64 blockSize at state+0x18. No expected image geometry comparison in this dispatch.',
              'hdisk_start 0x17DEC issues an asynchronous shell echo of the selected NBD path to lun.N/file (trailing &), then binds hddisk UDC. It checks only safe_system return < 0, not nonzero shell exit status or completion of background file write.',
              'fsg_lun_open 0x807385B0 samples inode size and queue logical block size, then caches bytes at LUN+8, total blocks at +0x10, block shift +0x28 and block size +0x2C.',
              'READ CAPACITY fragment 0x8073743C..0x80737484 reads cached LUN+0x10 and +0x2C, emits totalBlocks-1 and block size; it neither refreshes inode/queue metadata nor calls the remote client.',
              'nbd_alloc_config defaults block size to 1024. The 0x40000 immediate in fsg_lun_open at 0x8073862C is a file-mode bit test, not a capacity assignment.'
            ]}
    (HERE/'native_geometry_analysis.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({'kernel_functions':len(selected),'kernel_hits':[{'name':s['name'],'hits':s['constant_hits']} for s in selected if s['constant_hits']],
                      'userspace_hits':{k:v['immediate_hits'] for k,v in sources.items()}},indent=2))
if __name__=='__main__':main()
