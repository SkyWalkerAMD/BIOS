"""Local parser replay using all 13 observed HII instance structures.

This combines eight prior exact original FORMS observations with five newer
physical structures. It is a composite replay fixture, not a simultaneous live
database or a complete boot. Unknown strings/owners are not invented as trusted.
Bounds changes exist only in emulator memory; no CAP/ROM/PE is modified.
"""
from pathlib import Path
import collections
import hashlib
import json
import sys
import time
import uuid

H=Path(__file__).resolve().parent;B=H.parent;R=H.parents[3]
sys.path.insert(0,str(B/'parser_catalog05'))
import replay as original_model
experiment=B/'parser_catalog05/investigate_boundary.py'
text=experiment.read_text()
assert text.count('\nresults=[]')==1
ns={'__file__':str(experiment),'__name__':'imported_model_definitions_only'}
exec(compile(text.split('\nresults=[]')[0],str(experiment),'exec'),ns)
Base=ns['ExperimentVM'];controls=ns['control_evidence'];TSE=original_model.TSE
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_R14,UC_X86_REG_R15

def sha(data):return hashlib.sha256(data).hexdigest()
def binding(p):return {'path':p.relative_to(R).as_posix(),'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size}
HARDWARE=B/'hardware_delta07/capture_6e7a57f9729b082c'
REPORT=json.loads((HARDWARE/'reconciled.json').read_text())
MF=B/'hardware_delta07/component_manifest.json'
assert sha(MF.read_bytes())=='b46cc932ae102b3af307ed71d959e5340d2f0e147e7ce4ac6b22f0cd7526f767'
frozen_hardware=json.loads(MF.read_text())
for x in frozen_hardware['files']+frozen_hardware['external_bindings']:
    assert sha((R/x['path']).read_bytes())==x['sha256']
PATCHES=[(0x41010,'0f8223010000','0f8623010000'),(0x4112c,'0f86eefeffff','0f82eefeffff')]

class HardwareVM(Base):
    def __init__(self,changed=False,strict_bounds=False):
        super().__init__(changed=changed)
        assert self.original_sha=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
        assert self.static_sha=='e9b4799c79e23d75b39a123066c6ab80ed3f9176dfc57a50727968c5b1ec08f3'
        for obj in REPORT['objects']:
            guid=obj['package_list_guid'];raw=(R/obj['blob']['path']).read_bytes()
            assert sha(raw)==obj['sha256']
            body=raw+b'\x04\x00\x00\xdf'
            data=uuid.UUID(guid).bytes_le+original_model.D(20+len(body))+body
            existing=[h for h,p in self.package_models.items() if p['guid']==guid]
            if obj['kind']!=2:
                assert len(existing)==1
                model=self.package_models[existing[0]]
                model['data']=data;model['observed_handle']=obj['current_hii'];model['forms']=obj['forms']
                model['forms_observation']='D7 physical complete reconstruction'
            else:
                handle=0x920000+16*obj['instance_index']
                assert handle not in self.package_models
                self.package_models[handle]={'module':'NON_FV_25FD_INSTANCE_'+str(obj['instance_index']),
                    'data':data,'strings':{},'forms':obj['forms'],'observed_handle':obj['current_hii'],
                    'guid':guid,'forms_observation':'D7 physical; string payload and executable not exported'}
            self.input_bindings.append(binding(R/obj['blob']['path']))
        # Fix a reproducible order only. Mixed-capture opaque handles are never
        # used as pointers or claimed to identify the same instance across boots.
        self.handles=sorted(self.package_models)
        self.omitted=[]
        assert len(self.handles)==13 and sum(x['forms'] for x in self.package_models.values())==391
        self.iterations=[]
        if strict_bounds:
            for off,before,after in PATCHES:
                assert bytes(self.u.mem_read(TSE+off,6)).hex()==before
                self.u.mem_write(TSE+off,bytes.fromhex(after))
        def witness(u,address,size,context):
            index=int(u.reg_read(UC_X86_REG_R14));count=self.rd(u.reg_read(UC_X86_REG_R15))
            self.iterations.append(index)
            if strict_bounds:assert 1<=index<count
        self.u.hook_add(UC_HOOK_CODE,witness,begin=TSE+0x41020,end=TSE+0x41020)

def run(changed,strict_bounds):
    v=HardwareVM(changed,strict_bounds);start=time.monotonic()
    record={'management_actions_inserted':changed,'two_bounds_changes_in_emulator_only':strict_bounds,
            'replay_source_sha256':sha(Path(__file__).read_bytes()),
            'original_tse_sha256':v.original_sha,'original_spf_sha256':v.static_sha,
            'modelled_handles':len(v.handles),'modelled_forms':391,'inputs':v.input_bindings,
            'native_binary_artifact_created':False,'firmware_written':False}
    try:
        result=v.run();record['return']=hex(result)
        record['status']='PARSER_RETURNED' if result==0 else 'NATIVE_ERROR'
    except Exception as error:
        record['status']='REPLAY_STOPPED';record['error']=str(error)
    record.update(seconds=round(time.monotonic()-start,3),calls=dict(v.calls),
                  spf_guard_error=v.pool_guard_error,largest_static_index=max(v.iterations,default=None),
                  iterations=len(v.iterations),volatile_variable_models=v.writes,
                  unavailable_string_requests=[{'module':a,'token':b,'count':n} for (a,b),n in sorted(v.unknown_strings.items())])
    if record.get('return')=='0x0':
        record['native_pages']=v.summarize_pages();record['control_evidence']=controls(v)
        assert record['native_pages']['count']==396 and not record['native_pages']['missing_records']
    p=H/('changed_bounds.json' if changed else 'original_bounds.json' if strict_bounds else 'original_unmodified.json')
    p.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'case':p.name,'status':record['status'],'seconds':record['seconds'],
                     'native_pages':record.get('native_pages',{}).get('count'),
                     'controls':record.get('control_evidence',{}).get('control_count'),
                     'largest_static_index':record['largest_static_index'],'error':record.get('error')}),flush=True)
    return record

def main():
    unmodified=run(False,False)
    assert unmodified['status']=='REPLAY_STOPPED' and '41052' in unmodified.get('error','')
    a=run(False,True);b=run(True,True)
    assert a.get('return')=='0x0' and b.get('return')=='0x0'
    ac,bc=a['control_evidence'],b['control_evidence']
    assert ac['bound_pages']==bc['bound_pages'] and ac['unresolved_placeholders']==bc['unresolved_placeholders']
    assert not ac['management'] and len(bc['management'])==3
    assert {x['question'] for x in bc['management']}=={0xffd0,0xffd1,0xffd2}
    assert all(x['form']==0x271d and x['native_type']==27 and x['module']=='Setup' for x in bc['management'])
    assert bc['control_count']==ac['control_count']+3
    out={'status':'COMPOSITE_PHYSICAL_FORMS_PARSER_DIFFERENTIAL_PASSED_NOT_BOOT_QUALIFICATION',
         'inputs':[binding(Path(original_model.__file__)),binding(experiment),binding(MF),binding(HARDWARE/'reconciled.json')],
         'emulator_only_patches':[{'rva':hex(o),'before':a,'after':b} for o,a,b in PATCHES],
         'modelled_hii_instances':13,'modelled_ifr_forms':391,'native_pages_in_both':396,
         'original_bound_control_opcodes_and_types_equal':True,
         'control_counts':[ac['control_count'],bc['control_count']],
         'management_controls':bc['management'],'unresolved_native_placeholders':len(ac['unresolved_placeholders']),
         'limitations':['Composite observations across captures; no current simultaneous runtime identity claim.',
                        'Unknown native strings and ConfigAccess owner lookup remain NOT_FOUND models.',
                        'UEFI services, allocations and three volatile count variables are explicit models.',
                        'Original strict replay stops at source SPF overflow; two local branch experiments remove the extra iteration.',
                        'No complete startup, GUI, callback permission, password operation, CAP or FlashBack acceptance test.']}
    (H/'comparison.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'comparison':out['status'],'pages':396,'controls':out['control_counts']}),flush=True)

if __name__=='__main__':main()
