"""Fill one reserved read-only profile after exact static PE composition."""
import ctypes as C
import json,struct
from merge_pe import *

class Packed(C.LittleEndianStructure): _pack_=1
class Section(Packed): _fields_=[('name',C.c_char*8)]+[(n,C.c_uint32)for n in ['rva','virtual_bytes','raw_bytes','file_offset','characteristics']]
class Patch(Packed): _fields_=[(n,C.c_uint32)for n in ['module','rva','length','target_rva','mode']]+[('original',C.c_uint8*32),('installed',C.c_uint8*32)]
class Span(Packed): _fields_=[('rva',C.c_uint32),('length',C.c_uint32),('sha256',C.c_uint8*32)]
class Fixup(Packed): _fields_=[('rva',C.c_uint32),('reserved',C.c_uint32),('preferred_value',C.c_uint64)]
class Symbol(Packed): _fields_=[('name',C.c_char*40),('rva',C.c_uint32),('kind',C.c_uint32)]
class Layout(Packed):
    _fields_=[('magic',C.c_char*8)]+[(n,C.c_uint32)for n in ['revision','size','image_size','entry_rva','original_entry_rva','extension_rva',
      'extension_image_size','section_count','patch_count','span_count','fixup_count','export_count','trampoline_count','slot_rva','header_bytes','reserved']]+[
      ('header_sha256',C.c_uint8*32),('sections',Section*16),('patches',Patch*64),('spans',Span*256),('fixups',Fixup*256),('symbols',Symbol*192)]

def bind_layout(merged,composition):
    need(sha(merged)==composition['merged_sha256'],'composition binding')
    p=pefile.PE(data=merged);need(p.OPTIONAL_HEADER.ImageBase==0,'merged base zero')
    need('i05_static_layout'in composition['exports'],'compiled layout slot export required')
    at=composition['exports']['i05_static_layout'];off=raw_offset(p,at,C.sizeof(Layout))
    owner=section_at(p,at,C.sizeof(Layout));need(not owner.Characteristics&0x80000000,'layout slot must be readonly')
    need(merged[off:off+C.sizeof(Layout)]==b'W890SLOT'+b'\0'*(C.sizeof(Layout)-8),'exact unused layout placeholder')
    layout=Layout();layout.magic=b'W890L05';layout.revision=5;layout.size=C.sizeof(Layout)
    for k in ['image_size','entry_rva','original_entry_rva','extension_rva','extension_image_size']:setattr(layout,k,composition[k])
    layout.slot_rva=at;layout.header_bytes=p.OPTIONAL_HEADER.SizeOfHeaders
    need(layout.header_bytes==1024,'reviewed header size')
    hh=bytearray(merged[:layout.header_bytes]);nt=p.DOS_HEADER.e_lfanew;hh[nt+24+64:nt+24+68]=bytes(4)
    layout.header_sha256[:]=hashlib.sha256(hh).digest()
    sr=composition['original_sections']+composition['added_sections'];need(len(sr)<=16,'section count')
    layout.section_count=len(sr)
    for i,row in enumerate(sr):
        layout.sections[i].name=row['name'].encode()
        for k in ['rva','virtual_bytes','raw_bytes','file_offset','characteristics']:setattr(layout.sections[i],k,row[k])
    need(len(composition['patches'])<=64,'patch count');layout.patch_count=len(composition['patches'])
    for i,row in enumerate(composition['patches']):
        q=layout.patches[i];q.module=0;q.rva=row['rva'];q.length=row['bytes'];q.target_rva=row['target_rva'];q.mode=1 if row['mode']=='call'else 0
        q.original[:q.length]=bytes.fromhex(row['original_hex']);q.installed[:q.length]=bytes.fromhex(row['installed_hex'])
    sy=[(k,v,0)for k,v in sorted(composition['exports'].items())]+[(k,v,1)for k,v in sorted(composition['trampolines'].items())]
    need(len(sy)<=192,'symbol count');layout.export_count=len(composition['exports']);layout.trampoline_count=len(composition['trampolines'])
    for i,(name,rva,kind)in enumerate(sy):
        need(len(name.encode())<40,'bounded symbol name');layout.symbols[i].name=name.encode();layout.symbols[i].rva=rva;layout.symbols[i].kind=kind
    data=mapped(p);rr=relocations(p);regions=[];spans=[];fixups=[]
    for index,s in enumerate(p.sections):
        # Original mutable globals are not pinned. New code/constants are,
        # excluding the profile itself and loader-discardable relocation data.
        wanted=(s.Characteristics&0x20000000)or(index>=6 and not s.Characteristics&(0x80000000|0x02000000))
        if not wanted:continue
        begin=s.VirtualAddress;end=begin+s.Misc_VirtualSize;cuts=[]
        if begin<=at<end:
            need(at+C.sizeof(Layout)<=end,'layout must fit one readonly section');cuts.append((at,at+C.sizeof(Layout),'layout'))
        for rva in rr:
            if begin<=rva<end:
                need(rva+8<=end,'readonly relocation bounds');cuts.append((rva,rva+8,'fixup'))
                val=u64(data,rva);need(0<=val<layout.image_size,'readonly absolute pointer internal')
                fixups.append((rva,val))
        cursor=begin
        for lo,hi,kind in sorted(cuts):
            need(lo>=cursor,'overlapping readonly exclusions')
            if lo>cursor:spans.append((cursor,lo-cursor,hashlib.sha256(data[cursor:lo]).digest()))
            cursor=hi
        if cursor<end:spans.append((cursor,end-cursor,hashlib.sha256(data[cursor:end]).digest()))
        regions.append({'name':s.Name.rstrip(b'\0').decode(),'rva':begin,'length':end-begin})
    for pointer in composition.get('pointer_patches',[]):
        need(not any(r==pointer['rva']for r,_ in fixups),'duplicate identity pointer')
        need(u64(data,pointer['rva'])==pointer['installed_value'],'installed data target')
        fixups.append((pointer['rva'],pointer['installed_value']))
    need(0<len(spans)<=256 and len(fixups)<=256,'bounded readonly identity evidence')
    layout.span_count=len(spans);layout.fixup_count=len(fixups)
    for i,(rva,n,digest)in enumerate(spans):layout.spans[i].rva=rva;layout.spans[i].length=n;layout.spans[i].sha256[:]=digest
    for i,(rva,val)in enumerate(fixups):layout.fixups[i].rva=rva;layout.fixups[i].preferred_value=val
    result=bytearray(merged);result[off:off+C.sizeof(Layout)]=bytes(layout)
    struct.pack_into('<I',result,nt+24+64,0);mp=pefile.PE(data=bytes(result));struct.pack_into('<I',result,nt+24+64,mp.generate_checksum())
    # Postfill must not alter any hashed bytes or header identity.
    mi=mapped(pefile.PE(data=bytes(result)))
    for rva,n,digest in spans:need(hashlib.sha256(mi[rva:rva+n]).digest()==digest,'profile fill changed pinned span')
    hh=bytearray(result[:1024]);hh[nt+24+64:nt+24+68]=bytes(4)
    need(hashlib.sha256(hh).digest()==bytes(layout.header_sha256),'postfill header identity')
    report={**composition,'merged_sha256':sha(result),'static_layout':{'slot_rva':at,'slot_bytes':C.sizeof(Layout),'slot_sha256':sha(bytes(layout)),
      'header_sha256':bytes(layout.header_sha256).hex(),'pinned_regions':regions,'span_count':len(spans),'identity_fixup_count':len(fixups),
      'header_normalization':{'CheckSum':'zero','ImageBase':'accept only preferred zero or exact proved load base, then zero'},
      'profile_is_a_fixed_readonly_linked_symbol':True,'caller_must_prove_range_before_live_check':True,
      'not_session_authorization':True}}
    return bytes(result),report
