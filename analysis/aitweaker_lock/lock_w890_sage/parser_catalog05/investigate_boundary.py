"""Local differential experiment for the independently witnessed SPF read.

Only emulator memory is changed. This is not an accepted firmware patch: it
tests whether the inclusive final iteration explains the read beyond the SPF.
The immutable original replay/failure evidence and development PE stay intact.
Missing external HII and service/allocator models are still explicit limits.
"""
from pathlib import Path
import hashlib,json,time,uuid
from replay import CatalogVM,TSE,digest
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_R14,UC_X86_REG_R15

H=Path(__file__).resolve().parent

class ExperimentVM(CatalogVM):
    def volatile_count(self,a):
        name=bytes(self.u.mem_read(a[0],128)).decode('utf-16le',errors='replace').split('\0')[0]
        expected={
            'DynamicPageCount':('b63bf800-f267-4f55-9217-e97fb3b69846',(4,8)),
            'DynamicPageGroupCount':('537f1f99-6fc4-40b5-80b2-390b0753c4d0',(2,)),
            'DynamicPageGroupClass':('551941e5-0011-4d7f-83ed-e462cbabccc9',(14,)),
        }
        assert name in expected,('unmodeled name',name,a[2:4])
        guid,sizes=expected[name]
        assert bytes(self.u.mem_read(a[1],16))==uuid.UUID(guid).bytes_le
        assert a[2]==2 and a[3] in sizes,(name,a[2:4])
        data=bytes(self.u.mem_read(a[4],a[3]))
        if name=='DynamicPageCount':assert int.from_bytes(data,'little')<=4096
        self.writes.append({'name':name,'attributes':2,'size':a[3],'value':data.hex(),
                            'effect':'volatile model only, initial zero and final native count'})
        return 0

def control_evidence(v):
    table=v.rq(TSE+0xbaaf0);blob=v.rq(TSE+0xbabc0);cb=v.rq(TSE+0xbab08)
    def readable(p,n):
        return (v.static<=p and p+n<=v.static+v.static_extent) or any(a<=p and p+n<=a+size for a,size in v.live.items())
    pages=[];management=[];control_count=0;unbound_controls=[]
    for i in range(v.rd(table)):
        pd=blob+v.rd(table+4+4*i)
        assert readable(pd,32),('page descriptor extent',i,hex(pd))
        h=v.rq(pd);form=v.rw(pd+10)
        if h not in v.package_models:
            continue
        n=v.rd(pd+28);assert n<=4096 and readable(pd,32+4*n)
        original=[]
        for j in range(n):
            cd=cb+v.rd(pd+32+4*j)
            assert readable(cd,64),('control descriptor extent',i,j,hex(cd))
            op=v.rq(cd+40);kind=v.rw(cd+20);owner=v.rq(cd)
            if not op:
                # Retain the native placeholder as unresolved; do not invent
                # IFR bytes or count it as a verified active input control.
                item={'page':i,'control':j,'native_type':kind,'hii':owner,
                      'flags':v.rd(cd+28),'reason':'NULL_IFR_POINTER_NATIVE_PLACEHOLDER'}
                unbound_controls.append(item);original.append(['unresolved',item]);control_count+=1
                continue
            assert readable(op,2),('opcode header extent',i,j,hex(op))
            size=bytes(v.u.mem_read(op+1,1))[0]&127
            assert 2<=size<=127 and readable(op,size),('opcode extent',i,j,hex(op),size)
            code=bytes(v.u.mem_read(op,size))
            assert v.rq(cd)==h,('control HII owner',i,j)
            q=v.rw(op+6) if len(code)>=13 else None
            if code[:2]==b'\x0c\x0f' and q in (0xffd0,0xffd1,0xffd2):
                management.append({'page':i,'form':form,'question':q,'native_type':kind,'module':v.package_models[h]['module']})
            else:
                original.append([kind,code.hex()])
            control_count+=1
        encoded=json.dumps(original,separators=(',',':')).encode()
        pages.append({'index':i,'form':form,'hii':h,'module':v.package_models[h]['module'],
                      'original_controls':len(original),'control_opcode_and_type_sha256':digest(encoded)})
    return {'bound_pages':pages,'control_count':control_count,'management':management,
            'unresolved_placeholders':unbound_controls,
            'extent_check':'All raw page/control descriptors and every non-null IFR read are wholly inside a live modeled allocation or original SPF extent. Null IFR placeholders are recorded unresolved, never authorized.'}

def run(changed):
    v=ExperimentVM(changed=changed)
    # Immutable exact-image identity is checked in CatalogVM. Do not transform
    # any other conditional branch, alter count, or supply adjacent SPF memory.
    original=bytes(v.u.mem_read(TSE+0x4112c,6))
    assert original==bytes.fromhex('0f86eefeffff'),original.hex()
    experimental=bytes.fromhex('0f82eefeffff')
    v.u.mem_write(TSE+0x4112c,experimental)
    iterations=[]
    def witness(u,address,size,context):
        iterations.append(int(u.reg_read(UC_X86_REG_R14)))
        assert iterations[-1] < v.rd(u.reg_read(UC_X86_REG_R15))
    v.u.hook_add(UC_HOOK_CODE,witness,begin=TSE+0x41020,end=TSE+0x41020)
    result={'status':'BOUND_EXPERIMENT_RUNNING','scope':__doc__,
       'management_actions_inserted':changed,'original_tse_sha256':v.original_sha,
       'catalog_sha256':digest(v.catalog_path.read_bytes()),
       'emulator_only_change':{'rva':0x4112c,'before':original.hex(),'after':experimental.hex()},
       'applied_to_development_pe':False,'applied_to_firmware':False,
       'omitted_packages':v.omitted,'modeled_handles':len(v.handles),
       'source_sha256':digest(Path(__file__).read_bytes()),
       'replay_source_sha256':digest((H/'replay.py').read_bytes())}
    start=time.monotonic()
    try:
        r=v.run();result['return']=hex(r)
        result['status']='BOUND_EXPERIMENT_PARSER_RETURNED' if r==0 else 'BOUND_EXPERIMENT_NATIVE_ERROR'
    except Exception as e:
        result['status']='BOUND_EXPERIMENT_FAILED';result['error']=str(e)
    result.update(spf_guard_error=v.pool_guard_error,iterations=len(iterations),
                  largest_static_index=max(iterations,default=None),calls=dict(v.calls),
                  volatile_writes=v.writes,elapsed_seconds=round(time.monotonic()-start,3))
    try:result['native_pages']=v.summarize_pages()
    except Exception as e:result['inspection_error']=str(e)
    if result.get('return')=='0x0':
        try:result['control_evidence']=control_evidence(v)
        except Exception as e:result['control_inspection_error']=str(e)
    return result

results=[]
for changed in [False,True]:
    result=run(changed);results.append(result)
    print(json.dumps({k:v for k,v in result.items() if k not in ['scope','calls','native_pages','control_evidence']}),flush=True)
    if 'native_pages' in result:print(json.dumps({k:v for k,v in result['native_pages'].items() if k!='pages'}),flush=True)
comparison={'status':'UNAVAILABLE'}
if all('control_evidence'in r for r in results):
    a,b=[r['control_evidence']for r in results]
    comparison={'status':'PASS'if a['bound_pages']==b['bound_pages'] else'FAIL',
                'all_original_bound_page_control_bytes_and_types_equal':a['bound_pages']==b['bound_pages'],
                'original_management':a['management'],'added_management':b['management'],
                'original_control_count':a['control_count'],'changed_control_count':b['control_count']}
    comparison['unresolved_placeholders_equal']=a['unresolved_placeholders']==b['unresolved_placeholders']
    comparison['unresolved_placeholder_count']=len(a['unresolved_placeholders'])
    comparison['exactly_three_type27_security_actions']=not a['management'] and len(b['management'])==3 and all(x['module']=='Setup' and x['form']==0x271d and x['native_type']==27 for x in b['management']) and {x['question']for x in b['management']}=={0xffd0,0xffd1,0xffd2}
    if not comparison['exactly_three_type27_security_actions']:comparison['status']='FAIL'
print('COMPARISON',json.dumps(comparison),flush=True)
(H/'boundary_experiment.json').write_text(json.dumps({'status':'LOCAL_DIFFERENTIAL_EXPERIMENT_NOT_RELEASE_QUALIFICATION','comparison':comparison,'results':results},indent=2)+'\n')
