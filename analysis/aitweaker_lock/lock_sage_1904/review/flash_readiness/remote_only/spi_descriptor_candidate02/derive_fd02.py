"""Preserve FD01 and derive the smallest bounded-poll candidate from its capture."""
from pathlib import Path
import hashlib,json,shutil,difflib
HERE=Path(__file__).resolve().parent
OLD=HERE.parent/'spi_descriptor_candidate01'
HW=HERE.parents[3]/'remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
log=HW/'hardware-spifd01-1793681107320/hardware-log.txt'
assert sha(log)=='fa3a1d6c11c2787d7fed3740c707f422dbfe2a39464a6271b3d6f111c948f19a'
assert b'LAST_STATUS=0x3F01E820' in log.read_bytes()

def replace_once(text,old,new):
    assert text.count(old)==1,old
    return text.replace(old,new)

def labels(text):
    for old,new in [('SPI-DESCRIPTOR-01','SPI-DESCRIPTOR-02'),('SPI-DESCRIPTOR01','SPI-DESCRIPTOR02'),
                    ('SPI DESCRIPTOR 01','SPI DESCRIPTOR 02'),('SPIFD01','SPIFD02'),('FD01','FD02')]:
        text=text.replace(old,new)
    return text

for p in (OLD/'source').rglob('*'):
    if p.is_file():
        dest=HERE/p.relative_to(OLD);dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(p.read_bytes())
for name in ['prepare_candidate.py','prepare_transport_tests.py','verify_core.py','verify_frontend.py']:
    (HERE/name).write_text(labels((OLD/name).read_text(encoding='utf-8')),encoding='utf-8')

header=(OLD/'source/fd_core.h').read_text(encoding='utf-8')
header=replace_once(header,' ES failure_status;',' uint32_t poll_observations,busy_fgo_observations;\n ES failure_status;')
(HERE/'source/fd_core.h').write_text(header,encoding='utf-8')
core=(OLD/'source/fd_core.c').read_text(encoding='utf-8')
core=replace_once(core,
'''    if(FAILED(rd(io,r,STS,&s)))return r->failure_status;r->last_status=s;
    if(!status_valid(s,1)||(s&0xffff0000U)!=0x3f000000U)return fail(r,11,STS,ERR(7));''',
'''    if(FAILED(rd(io,r,STS,&s)))return r->failure_status;r->last_status=s;r->poll_observations++;
    /* FD01 physically observed FGO=1 together with SCIP=1, contrary to the
     * manual's read-zero wording. Tolerate ONLY that exact error-free busy
     * value as a reason to read again. No MMIO write or data read occurs here.
     * Idle checks remain unchanged and completion still requires FGO=0. */
    if(s==0x3f01e820U)r->busy_fgo_observations++;
    else if(!status_valid(s,1)||(s&0xffff0000U)!=0x3f000000U||(s&(BUSY|DONE))==(BUSY|DONE))return fail(r,11,STS,ERR(7));''')
(HERE/'source/fd_core.c').write_text(core,encoding='utf-8')
front=labels((OLD/'source/frontend.inc').read_text(encoding='utf-8'))
front=replace_once(front,' field("READ_CYCLE_START_ATTEMPTS",r->go_attempts,8);',
                  ' field("POLL_OBSERVATIONS",r->poll_observations,8);field("EXACT_BUSY_FGO_OBSERVATIONS",r->busy_fgo_observations,8);\n field("READ_CYCLE_START_ATTEMPTS",r->go_attempts,8);')
(HERE/'source/frontend.inc').write_text(front,encoding='utf-8')

test=(HERE/'verify_core.py').read_text(encoding='utf-8')
test=test.replace("state['status']=0x3f00e801","state['status']=opt.get('completion_status',0x3f00e801)")
test=test.replace("state['status']=0x3f00e820","state['status']=opt.get('busy_status',0x3f00e820)")
test=test.replace('result+56','result+64').replace("struct.unpack('<12IQ',u.mem_read(result,56))","struct.unpack('<14IQ',u.mem_read(result,64))")
test=test.replace("'last_status','failure_status'","'last_status','poll_observations','busy_fgo_observations','failure_status'")
test=replace_once(test,'for bit in [1,2,11,12,14,15,16,17,21,31]:', 'for bit in [1,2,11,12,14,15,17,21,31]:')
test=replace_once(test,"    add('slower_done',polls=9)",'''    add('slower_done',polls=9)
    add('captured_FD01_busy_FGO_then_done',busy_status=0x3f01e820)
    add('captured_busy_FGO_extended_wait',busy_status=0x3f01e820,polls=20)
    add('busy_FGO_timeout_no_second_command',busy_status=0x3f01e820,polls=10001,expected_stage=13)
    for value in [0x3f01e800,0x3f01e801,0x3f01e821,0x3f01e822,0x3f01e824,0x3f03e820,0x3e01e820]:
        add(f'only_exact_busy_FGO_allowed_{value:08x}',busy_status=value,expected_stage=11)
    add('GO_still_set_on_idle_completion',completion_status=0x3f01e801,expected_stage=11)
    add('FGO_one_without_SCIP_or_DONE',completion_status=0x3f01e800,expected_stage=11)
    add('BUSY_and_DONE_ambiguous',busy_status=0x3f00e821,expected_stage=11)''')
test=replace_once(test,"    if opt.get('no_go'):assert state['go']==0",'''    if opt.get('busy_status')==0x3f01e820:
        assert record['busy_fgo_observations']>0
        if not expect:assert record['busy_fgo_observations']==128*(opt.get('polls',2)-1)
    if opt.get('no_go'):assert state['go']==0''')
(HERE/'verify_core.py').write_text(test,encoding='utf-8')

test=(HERE/'verify_frontend.py').read_text(encoding='utf-8')
test=replace_once(test,"if model['poll']>=2:model['waiting']=False;model['status']=0x3f00e801",
                  "if model['poll']>=opt.get('polls',2):model['waiting']=False;model['status']=opt.get('completion_status',0x3f00e801)")
test=replace_once(test,'model.update(status=0x3f00e820,waiting=True,poll=0,go=model[\'go\']+1)',
                  'model.update(status=opt.get(\'busy_status\',0x3f00e820),waiting=True,poll=0,go=model[\'go\']+1)')
test=replace_once(test,"    add('complete_original_CPU_IO2_path',pass_capture=True)",'''    add('complete_original_CPU_IO2_path',pass_capture=True)
    add('captured_busy_FGO_native_CPU_IO2',busy_status=0x3f01e820,pass_capture=True)
    add('busy_FGO_native_timeout',busy_status=0x3f01e820,polls=10001,allow_reads=True,allow_writes=True)
    add('native_FGO_idle_refused',completion_status=0x3f01e801,allow_reads=True,allow_writes=True)
    add('native_busy_FGO_error_refused',busy_status=0x3f01e822,allow_reads=True,allow_writes=True)''')
(HERE/'verify_frontend.py').write_text(test,encoding='utf-8')

parser=(HW/'read_spi_descriptor01_qr.py').read_text(encoding='utf-8')
parser=labels(parser)
parser=replace_once(parser,"    if text.count('DESCRIPTOR_TWO_PASSES_MATCH=YES\\r\\n')!=1:",
                  "    if not 128<=field('POLL_OBSERVATIONS')<=1280000:raise ValueError('Poll count bound')\n    if not 0<=field('EXACT_BUSY_FGO_OBSERVATIONS')<field('POLL_OBSERVATIONS'):raise ValueError('Busy FGO count bound')\n    if text.count('DESCRIPTOR_TWO_PASSES_MATCH=YES\\r\\n')!=1:")
(HW/'read_spi_descriptor02_qr.py').write_text(parser,encoding='utf-8')
operation=(HW/'operations/capture_spi_descriptor01.mjs').read_text(encoding='utf-8')
operation=operation.replace('SPI-DESCRIPTOR-01','SPI-DESCRIPTOR-02').replace('spifd01','spifd02').replace('read_spi_descriptor01','read_spi_descriptor02')
(HW/'operations/capture_spi_descriptor02.mjs').write_text(operation,encoding='utf-8')
diff=''
for name in ['source/fd_core.c','source/fd_core.h','source/frontend.inc','verify_core.py','verify_frontend.py']:
    diff+=''.join(difflib.unified_diff((OLD/name).read_text(encoding='utf-8').splitlines(True),(HERE/name).read_text(encoding='utf-8').splitlines(True),fromfile='FD01/'+name,tofile='FD02/'+name))
(HERE/'FD01-to-FD02.patch').write_text(diff,encoding='utf-8')
(HERE/'derivation.json').write_text(json.dumps({'scope':'Single exact busy-value tolerance, only within bounded post-GO read polling. No changed write whitelist or protection/identity/idle gates.',
    'original_source_sha256':sha(OLD/'source/fd_core.c'),'physical_log':str(log),'physical_log_sha256':sha(log),
    'manual_discrepancy_retained':'Observed FGO1 during SCIP1 differs from manual read-zero wording; not declared documented normal behavior.',
    'no_new_hardware_access':True,'script_sha256':sha(Path(__file__))},indent=2)+'\n',encoding='utf-8')
print('Derived isolated FD02; previous candidate and hardware evidence unchanged.')
