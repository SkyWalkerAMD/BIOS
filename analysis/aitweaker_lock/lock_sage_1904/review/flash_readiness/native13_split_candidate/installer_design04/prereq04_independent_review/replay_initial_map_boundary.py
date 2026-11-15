"""Independent boundary check on copied compiled PE bytes; no firmware execution.
No candidate build or source is changed. Synthetic EFI services are explicit.
The first copied build already includes the author's callback-boundary fix.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct,sys
OUT=Path(__file__).resolve().parent;PROBE=OUT.parent/'prerequisite_probe04'
ROOT=next(p for p in OUT.parents if (p/'tools/pydeps').is_dir())
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn.x86_const import *
B=0x1000000;D=0x2000000;STACK=0x3000000;POOL=0x4000000;STUB=0x5000000
ERR=lambda n:0x8000000000000000|n
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--snapshot',default='initial');args=parser.parse_args()
    assert re.fullmatch(r'[a-z0-9_]+',args.snapshot)
    snap=OUT/('initial_snapshot' if args.snapshot=='initial' else 'map_'+args.snapshot+'_snapshot');snap.mkdir(parents=True,exist_ok=True)
    selected=['build/SageNative13Prerequisite04.efi','build/probe.map','build/build.json','source/pagewalk.inc','source/owned_fixture.inc','source/preflight.c','source/efi.h']
    records=[]
    for name in selected:
        src=PROBE/name;dst=snap/name;dst.parent.mkdir(parents=True,exist_ok=True)
        if dst.exists():pass  # Immutable first-observed snapshot is replayed on reruns.
        else:dst.write_bytes(src.read_bytes())
        records.append({'path':name,'bytes':dst.stat().st_size,'sha256':sha(dst)})
    pe_path=snap/'build/SageNative13Prerequisite04.efi';maptext=(snap/'build/probe.map').read_text(encoding='utf8')
    symbols={m.group(1):int(m.group(2),16) for m in re.finditer(r'^\s+\w+:\w+\s+(\S+)\s+([0-9a-fA-F]{16})\s',maptext,re.M)}
    original=pefile.PE(str(pe_path)).OPTIONAL_HEADER.ImageBase
    sym=lambda name:B+symbols[name]-original
    results=[]
    for case in ['ending_in_buffer_too_small','ending_in_allocate_pool','ending_in_free_pool']:
        pe=pefile.PE(str(pe_path));pe.relocate_image(B);img=pe.get_memory_mapped_image()
        u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(B,(len(img)+4095)&~4095);u.mem_write(B,img)
        for a,n in [(D,0x10000),(STACK,0x10000),(POOL,0x100000),(STUB,0x10000)]:u.mem_map(a,n)
        def w64(a,v):u.mem_write(a,struct.pack('<Q',v))
        def r64(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
        w64(sym('system_table'),D);w64(D+0x60,D+0x1000)
        has_old=case!='ending_in_allocate_pool';w64(sym('map'),POOL if has_old else 0);w64(sym('map_capacity'),48 if has_old else 0);w64(sym('map_bytes'),48 if has_old else 0)
        w64(sym('stride'),48);u.mem_write(sym('prerequisite_ended'),bytes(4))
        callbacks={STUB+0x100:'GetMemoryMap',STUB+0x200:'FreePool',STUB+0x300:'AllocatePool'}
        for a in callbacks:u.mem_write(a,b'\xc3')
        w64(D+0x1000+0x38,STUB+0x100);w64(D+0x1000+0x48,STUB+0x200);w64(D+0x1000+0x40,STUB+0x300)
        calls=[];forbidden=[]
        def hook(uc,address,size,unused):
            if address not in callbacks:return
            name=callbacks[address];ended=struct.unpack('<I',uc.mem_read(sym('prerequisite_ended'),4))[0]
            calls.append({'service':name,'ending_already_observed':bool(ended)})
            if ended:forbidden.append(name);uc.emu_stop();return
            a=[uc.reg_read(r) for r in [UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9]]
            status=0
            if name=='GetMemoryMap':
                w64(a[0],96);w64(a[3],48);status=ERR(5)
                if case=='ending_in_buffer_too_small':uc.mem_write(sym('prerequisite_ended'),struct.pack('<I',1))
            elif name=='FreePool':
                assert a[0]==POOL
                if case=='ending_in_free_pool':uc.mem_write(sym('prerequisite_ended'),struct.pack('<I',1))
            elif name=='AllocatePool':
                assert a[0]==4;w64(a[2],POOL+0x10000)
                if case=='ending_in_allocate_pool':uc.mem_write(sym('prerequisite_ended'),struct.pack('<I',1))
            uc.reg_write(UC_X86_REG_RAX,status)
        u.hook_add(UC_HOOK_CODE,hook);sp=STACK+0xf008;w64(sp,STUB+0xff00);u.reg_write(UC_X86_REG_RSP,sp)
        u.emu_start(sym('refresh_map'),STUB+0xff00,count=200000)
        expected_calls={
            'ending_in_buffer_too_small':['GetMemoryMap'],
            'ending_in_allocate_pool':['GetMemoryMap','AllocatePool'],
            'ending_in_free_pool':['GetMemoryMap','FreePool'],
        }[case]
        ended=struct.unpack('<I',u.mem_read(sym('prerequisite_ended'),4))[0]
        returned=u.reg_read(UC_X86_REG_RIP)==STUB+0xff00
        return_value=u.reg_read(UC_X86_REG_RAX)&0xffffffff
        assert [c['service'] for c in calls]==expected_calls, (case,calls)
        assert ended==1 and returned and return_value==0, (case,ended,returned,return_value)
        results.append({'case':case,'actual_compiled_function':'refresh_map','calls':calls,
                        'expected_nonempty_service_path_observed':True,'ending_flag_observed':ended,
                        'returned_to_sentinel':returned,'return_value':return_value,
                        'service_after_ending':forbidden,'counterexample_reproduced':bool(forbidden)})
    status='EBS_CALLBACK_BOUNDARY_COUNTEREXAMPLES_REPRODUCED' if any(r['counterexample_reproduced'] for r in results) else 'NO_SERVICE_AFTER_ENDING_IN_THREE_COMPILED_MAP_CASES'
    result={'status':status,'scope':'Copied compiled PE refresh_map under Unicorn; synthetic service callbacks set the exact ending global. All copied builds already include the callback-boundary fix; this is not a replay of the earlier source defect. Not a physical EBS event or whole-firmware test.','binary_sha256':sha(pe_path),'snapshot_files':records,'cases':results}
    output=OUT/('initial_map_boundary_replay.json' if args.snapshot=='initial' else 'map_'+args.snapshot+'_boundary_replay.json')
    output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':result['status'],'binary_sha256':result['binary_sha256'],'cases':[{k:v for k,v in r.items() if k in ['case','service_after_ending']} for r in results]},indent=2))
if __name__=='__main__':main()
