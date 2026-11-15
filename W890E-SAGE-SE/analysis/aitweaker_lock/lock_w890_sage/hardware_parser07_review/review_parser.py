"""Independent read-only fixture, branch, and differential replay review.

Imports only definitions from the frozen producers and calls VM.run directly;
never calls their report-writing entry points. Writes this directory only.
"""
from pathlib import Path
import sys, json, hashlib, re, struct, time, collections, uuid
sys.dont_write_bytecode = True
H = Path(__file__).resolve().parent
B = H.parent
R = B.parents[2]
P = B / 'hardware_parser07'
sys.path[:0] = [str(R / 'tools/pydeps'), str(P)]
import replay_hardware as m
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import *

def sha(b): return hashlib.sha256(b).hexdigest()
def bind(p): return {'path': p.relative_to(R).as_posix(), 'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
def load(p): return json.loads(p.read_text())
def verify_manifest():
    p = P / 'component_manifest.json'
    assert sha(p.read_bytes()) == 'eb5cbb859d7e49cd69315d7e133f6a58f7e077dd8467db2b9a82a665d7829104'
    d = load(p)
    for x in d['files'] + d['external_bindings']: assert bind(R / x['path']) == x
    return {'manifest': bind(p), 'local': len(d['files']), 'external': len(d['external_bindings'])}

def package_forms(data):
    assert len(data) == int.from_bytes(data[16:20], 'little')
    pos = 20; output = []
    while pos < len(data):
        size = int.from_bytes(data[pos:pos+3], 'little'); kind = data[pos+3]
        assert size >= 4 and pos + size <= len(data)
        blob = data[pos:pos+size]
        if kind == 2:
            offset = 4; stack = []; rows = []
            while offset < size:
                op, n = blob[offset], blob[offset+1] & 127
                scope = blob[offset+1] >> 7
                assert n >= 2 and offset + n <= size
                code = blob[offset:offset+n]
                if op == 0x29:
                    assert n == 2 and not scope and stack
                    stack.pop()
                else:
                    if op == 1:
                        fs = next((x[1] for x in reversed(stack) if x[0] == 0x0e), None)
                        assert fs and n >= 6
                        rows.append({'formset': fs, 'form': int.from_bytes(code[2:4], 'little')})
                    if scope:
                        stack.append((op, str(uuid.UUID(bytes_le=code[2:18])) if op == 0x0e else None))
                offset += n
            assert offset == size and not stack
            output.append({'bytes': size, 'sha256': sha(blob), 'forms': rows})
        pos += size
    assert pos == len(data)
    return output

def fixture_inventory(v):
    # Independently parse the prior physical F6 records rather than trust the
    # reconciler's baseline_match booleans. Handles are never equated across boots.
    log = B / 'remote_172_20_2_245/hardware-inventory01-1794115320552-227fa99e/hardware-log.txt'
    raw = log.read_bytes()
    assert sha(raw) == '932c0a5e1f051b6160982d5fe95ab17bac3211239b0d59ba2ed84839bf618331'
    text = raw.decode('ascii')
    fingerprint = re.findall(r'^F6 H=([0-9A-F]{16}) G=([0-9A-F-]{36}) P=([0-9A-F]{4}) L=([0-9A-F]{8}) S=([0-9A-F]{64})\r?$', text, re.M)
    reported = {h: (g.lower(), int(n)) for g,h,n in re.findall(r'^HII ([0-9A-F-]{36}) handle=0x([0-9A-F]{16}) forms=(\d+) ', text, re.M)}
    assert len(fingerprint) == len(reported) == 13
    physical = collections.Counter()
    for h,g,i,n,digest in fingerprint:
        assert int(i,16) == 0 and reported[h][0] == g.lower()
        physical[(g.lower(), int(n,16), digest.lower(), reported[h][1])] += 1
    modeled = collections.Counter(); rows = []
    for handle in v.handles:
        p = v.package_models[handle]; forms = package_forms(p['data'])
        assert len(forms) == 1 and len(forms[0]['forms']) == p['forms']
        f = forms[0]
        modeled[(p['guid'].lower(), f['bytes'], f['sha256'], len(f['forms']))] += 1
        rows.append({'model_handle': hex(handle), 'model_module': p['module'],
                     'guid': p['guid'], 'forms': p['forms'], 'bytes': f['bytes'],
                     'sha256': f['sha256'], 'input_observation': p.get('forms_observation', 'original static package, earlier HII06 hash match'),
                     'cross_boot_instance_identity': False})
    assert modeled == physical
    assert len(rows) == 13 and sum(x['forms'] for x in rows) == 391
    d7 = [x for x in rows if x['input_observation'].startswith('D7')]
    assert len(d7) == 5 and sum(x['forms'] for x in d7) == 176
    return {'rows': rows, 'physical_fingerprint_multiset_equal': True,
            'earlier_physical_log': bind(log), 'd7_instances': 5, 'd7_forms': 176,
            'remaining_original_instances': 8, 'remaining_original_forms': 215}

def loop_contract(count, mode, raw):
    tse, spf, stack, fake = 0x2000000, 0x19000000, 0x5000000, 0x6000000
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    pe = pefile.PE(str(B / 'navigation/modules/AMITSE.efi')); pe.relocate_image(tse)
    u.mem_map(tse,0x200000); u.mem_write(tse,pe.get_memory_mapped_image())
    u.mem_map(spf,0xf3000); u.mem_write(spf,raw)
    u.mem_map(stack,0x10000); u.mem_map(fake,0x10000)
    q = lambda n: struct.pack('<Q', n)
    u.mem_write(spf+0x60,struct.pack('<I',count))
    for rva,value in [(0xbab10,spf+0x60),(0xbab20,spf),(0xbab18,spf+0xf2394),(0xaff68,12)]:
        u.mem_write(tse+rva,q(value))
    for j,(rva,before,after) in enumerate(m.PATCHES):
        assert bytes(u.mem_read(tse+rva,6)).hex() == before
        if mode == 'both' or (mode == 'tail_only' and j == 1): u.mem_write(tse+rva,bytes.fromhex(after))
    u.reg_write(UC_X86_REG_RSP,stack+0x8000); u.reg_write(UC_X86_REG_R13,1)
    u.reg_write(UC_X86_REG_RDI,fake); u.reg_write(UC_X86_REG_RBX,fake+0x8000)
    state = {'count':count,'mode':mode,'indices':[],'lookup_model_calls':0}
    def hook(u,addr,size,_):
        if addr == tse+0x41023:
            i = u.reg_read(UC_X86_REG_R14); state['indices'].append(i)
            if i >= count:
                state['stop']='DECLARED_ARRAY_BOUND'; u.emu_stop()
        elif addr == tse+0x41dcc:
            state['lookup_model_calls']+=1
            rsp = u.reg_read(UC_X86_REG_RSP)
            target = int.from_bytes(u.mem_read(rsp,8),'little')
            u.reg_write(UC_X86_REG_RAX,11);u.reg_write(UC_X86_REG_RSP,rsp+8);u.reg_write(UC_X86_REG_RIP,target)
        elif addr in (tse+0x41132,tse+0x41139): state['stop']='LOOP_EXIT';u.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(tse+0x40fff,0,count=1000000)
    expected_safe = mode=='both' or count==0 or (mode=='tail_only' and count>=2)
    if expected_safe:
        assert state['stop']=='LOOP_EXIT' and state['indices']==list(range(1,count))
    else:
        assert state['stop']=='DECLARED_ARRAY_BOUND' and state['indices'][-1]==count
    return state

def main():
    initial = verify_manifest()
    sources = list((R/'analysis/workstation_20261008/W890_SAGE_0603').rglob('434 AMITSESetupData/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/0 FE612B72-203C-47B1-8560-A66D946EB371/body.bin'))
    assert len(sources)==1
    raw=sources[0].read_bytes()
    assert len(raw)==0xf245c and sha(raw)=='e9b4799c79e23d75b39a123066c6ab80ed3f9176dfc57a50727968c5b1ec08f3'
    bounds=[loop_contract(c,mode,raw) for c in (0,1,2,379) for mode in ('original','tail_only','both')]
    rows=[]; inventory=None; original_text=None
    for changed,strict in [(False,False),(False,True),(True,True)]:
        v=m.HardwareVM(changed=changed,strict_bounds=strict)
        section=next(x for x in v.pe.sections if x.Name.rstrip(b'\0')==b'.text')
        code=bytes(v.u.mem_read(m.TSE+section.VirtualAddress,section.Misc_VirtualSize))
        if original_text is None: original_text=code
        differing=[section.VirtualAddress+i for i,(x,y) in enumerate(zip(original_text,code)) if x!=y]
        assert differing==([0x41011,0x4112d] if strict else [])
        if not changed: current_inventory=fixture_inventory(v)
        if inventory is None: inventory=current_inventory
        start=time.monotonic(); result=None; error=None
        try: result=v.run()
        except Exception as e: error=str(e)
        row={'changed_forms':changed,'strict_loop':strict,'result':result,'error':error,
             'seconds':round(time.monotonic()-start,3), 'text_changed_rvas':differing,
             'largest_source_index':max(v.iterations,default=None),'iterations':len(v.iterations)}
        frozen=load(P/('changed_bounds.json' if changed else 'original_bounds.json' if strict else 'original_unmodified.json'))
        assert frozen['replay_source_sha256']==sha((P/'replay_hardware.py').read_bytes())
        if strict:
            assert result==0 and error is None
            pages=v.summarize_pages(); controls=m.controls(v)
            assert pages==frozen['native_pages'] and controls==frozen['control_evidence']
            assert pages['count']==396 and not pages['missing_records']
            row.update(native_pages=pages['count'],controls=controls['control_count'],
                       bound_pages_sha256=sha(json.dumps(controls['bound_pages'],sort_keys=True).encode()),
                       management=controls['management'],placeholders=len(controls['unresolved_placeholders']))
        else:
            assert result is None and '190f4ce6/2' in error and '2041052' in error
            assert row['largest_source_index']==379
        assert bytes(v.u.mem_read(m.TSE+section.VirtualAddress,section.Misc_VirtualSize))==code
        rows.append(row)
        print(json.dumps({'changed':changed,'strict':strict,'seconds':row['seconds'],'reproduced':True}),flush=True)
    assert rows[1]['bound_pages_sha256']==rows[2]['bound_pages_sha256']
    assert [r['controls'] for r in rows[1:]]==[13827,13830]
    assert not rows[1]['management'] and len(rows[2]['management'])==3
    assert {x['question'] for x in rows[2]['management']}=={0xffd0,0xffd1,0xffd2}
    assert all(x['form']==0x271d and x['native_type']==27 and x['module']=='Setup' for x in rows[2]['management'])
    assert verify_manifest()==initial
    out={'status':'INDEPENDENT_BOUNDED_REPLAY_REPRODUCED_NOT_FIRMWARE_PATCH_APPROVAL',
         'review_script':bind(Path(__file__)),'frozen_inputs':initial,'fixture_inventory':inventory,
         'original_spf':bind(sources[0]),'bounds_cases':bounds,'parser_cases':rows,
         'additional_dependency':bind(R/'analysis/aitweaker_lock/inspect_setup.py'),
         'limits':['UEFI/allocator/string/ConfigAccess boundaries remain the same explicit models; independent execution does not remove them.',
                   'The12 loop cases model41DCC as synthetic-last-package; they prove only loop bound comparisons.',
                   'Matching thirteen observed hashes is a cross-capture multiset reconciliation, not persistent instance or simultaneous database identity.',
                   'Unmodified stop is a real native read outside the declared source in this isolated model, not a demonstrated hardware crash.',
                   'No mutable branch changes were applied to any file, development PE, CAP, firmware or hardware.']}
    (H/'replay_review.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'status':out['status'],'bounds':len(bounds),'parser_cases':len(rows)}))

if __name__=='__main__':main()
