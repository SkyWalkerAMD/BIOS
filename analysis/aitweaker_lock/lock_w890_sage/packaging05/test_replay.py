"""Compare the actual original Save window to its composed PC-relative replay."""
from merge_pe import *
import unicorn
from unicorn.x86_const import *
ext=(HERE/'build/LAYOUT-FIXTURE.dll').read_bytes();orig=baseline()
patch={'rva':0x1fd58,'original_hex':'488d0df9360700e8a009ffff44382d5d000900','export':'i05_fixture_hook','mode':'jmp',
       'trampoline':'save_original','pc_relative_targets':[{'rva':0x1fd58,'target':0x93458,'kind':'rip'},
          {'rva':0x1fd5f,'target':0x10704,'kind':'call'},{'rva':0x1fd64,'target':0xafdc8,'kind':'rip'}]}
merged,report=compose(ext,sha(ext),'i05_fixture_entry',[patch]);STOP=0x9000000;STACK=0xa000000;rows=[]
def replay(raw,base,rva):
    pe=pefile.PE(data=raw);im=bytearray(mapped(pe))
    for r in relocations(pe):struct.pack_into('<Q',im,r,u64(im,r)+base)
    mu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64);mu.mem_map(base,align(len(im),4096));mu.mem_write(base,bytes(im))
    mu.mem_map(STACK,0x10000);mu.reg_write(UC_X86_REG_RSP,STACK+0xf000)
    regs=[UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_RBP,UC_X86_REG_RSI,UC_X86_REG_RDI,
        UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_R12,UC_X86_REG_R13,UC_X86_REG_R14,UC_X86_REG_R15]
    for x in regs:mu.reg_write(x,0x11110000+x)
    seen=[]
    def code(uc,address,size,context):
        if address==base+0x10704:
            seen.append({'target':address-base,'rcx':uc.reg_read(UC_X86_REG_RCX)-base})
            # Explicit common callee model; this test covers trampoline copying,
            # not the already separately reviewed Save notification body.
            sp=uc.reg_read(UC_X86_REG_RSP);ret=u64(bytes(uc.mem_read(sp,8)),0)
            uc.reg_write(UC_X86_REG_RAX,0xabcdef);uc.reg_write(UC_X86_REG_RSP,sp+8);uc.reg_write(UC_X86_REG_RIP,ret)
    mu.hook_add(unicorn.UC_HOOK_CODE,code)
    mu.emu_start(base+rva,base+0x1fd6b,count=10000);need(mu.reg_read(UC_X86_REG_RIP)==base+0x1fd6b,'resume')
    state=[mu.reg_read(x)for x in regs+[UC_X86_REG_RSP,UC_X86_REG_EFLAGS]]
    return state,seen,bytes(mu.mem_read(STACK+0xf000,0x1000))
for base in [0x20000000,0x120000000]:
    a=replay(orig,base,0x1fd58);b=replay(merged,base,report['trampolines']['save_original'])
    need(a==b,'original/relocated state differs');need(a[1]==[{'target':0x10704,'rcx':0x93458}],'notification target/GUID')
    rows.append({'case':'actual_Save_window_same_operands_call_flags_and_resume','base':hex(base),'passed':True,'callee_body':'explicit_common_model'})
for name,pc in [('missing_target_approval',[]),('wrong_target',patch['pc_relative_targets'][:2])]:
    try:compose(ext,sha(ext),'i05_fixture_entry',[{**patch,'pc_relative_targets':pc}])
    except ValueError as e:rows.append({'case':name,'passed':True,'rejection':str(e)})
    else:raise AssertionError(name)
report.update(status='PASS_EXACT_SAVE_REPLAY_RELOCATION_ONLY',cases=rows,saved_firmware_candidate=False,
    bindings=[{'path':str(p),'sha256':sha(p.read_bytes())}for p in [HERE/'test_replay.py',HERE/'merge_pe.py',HERE/'build/LAYOUT-FIXTURE.dll']],
    limits=['Original window executes, but its notification callee uses the same explicit return model in both runs.',
            'Not a full Save implementation, whole driver, boot or release validation.'])
(HERE/'save_replay_test.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'cases':len(rows)}))
