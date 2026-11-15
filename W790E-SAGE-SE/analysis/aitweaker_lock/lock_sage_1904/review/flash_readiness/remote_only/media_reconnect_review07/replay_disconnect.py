"""Original ARM receiver, dispatch and cleanup in synthetic memory only.

All imported network, filesystem, thread, device and session calls are trapped.
Gadget stop and NBD boundaries are recorded scalar stubs, never host operations.
"""
from pathlib import Path
import hashlib,importlib.util,json,struct,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
spec=importlib.util.spec_from_file_location('capacity_vm',REMOTE/'media_attach_review02/replay_capacity.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
U=m.U;R=m.R;P=m.P;STATE=m.STATE;FRAME=m.FRAME;GADGET=0x2e200;FEATURES=0x12eb00
def frame(op):
    b=bytearray(62);b[:8]=b'IUSB    ';b[12:16]=P(30);b[19]=128;b[41]=op
    b[11]=(-sum(b))&255
    return bytes(b)
def run(name,kind,unbind=False,last_opcode=0xf3):
    u=m.new_vm();calls=[];entries=[];cursor=0;done=False
    packet=frame(0xf7 if kind=='f7' else 0xf3)
    thunks={int(x['address'],16):x['name'] for x in json.loads((REMOTE/'media_attach_review02/hdserver_decompile/function_inventory.json').read_text())['functions'] if x['thunk']}
    def word(p):return struct.unpack('<I',u.mem_read(p,4))[0]
    def ret(v):u.reg_write(R.UC_ARM_REG_R0,v&0xffffffff);u.reg_write(R.UC_ARM_REG_PC,u.reg_read(R.UC_ARM_REG_LR))
    def hook(uc,a,size,_):
        nonlocal cursor,done
        if a==0x1579c:done=True;uc.emu_stop();return
        if a in [0x17054,0x16fd0,0x13770,0x12e68,0x149e4,0x130b4,0x17de0,0x13838,0x138c0]:entries.append(hex(a))
        if a==0x180b4:
            calls.append({'call':'hdisk_stop_boundary','instance':uc.reg_read(R.UC_ARM_REG_R0)});ret(0);return
        if a not in thunks:return
        n=thunks[a];r0=uc.reg_read(R.UC_ARM_REG_R0);r1=uc.reg_read(R.UC_ARM_REG_R1);r2=uc.reg_read(R.UC_ARM_REG_R2)
        if n.startswith('IDBG_') or n=='puts':ret(0);return
        if n=='sigwrap_select':ret(1);return
        if n=='sigwrap_recv':
            count=0 if kind=='eof' else min(r2,len(packet)-cursor)
            if count:uc.mem_write(r1,packet[cursor:cursor+count]);cursor+=count
            calls.append({'call':n,'returned':count});ret(count);return
        if n=='memset':uc.mem_write(r0,bytes([r1&255])*r2);ret(r0);return
        if n=='memcpy':uc.mem_write(r0,bytes(uc.mem_read(r1,r2)));ret(r0);return
        if n=='GetVMediaCfg':
            uc.mem_write(r0,bytes(32));uc.mem_write(r0+4,P(int(unbind)));calls.append({'call':n,'mode':int(unbind)});ret(0);return
        if n=='nbd_disconnect':calls.append({'call':n,'state_pointer':hex(r0)});ret(0);return
        if n=='nbd_write_res':calls.append({'call':n,'result':-1});ret(-1);return
        if n=='safe_system':
            b=bytes(uc.mem_read(r0,256)).split(b'\0')[0].decode('ascii');calls.append({'call':'safe_system_stub_only','command_literal':b});ret(0);return
        if n in ['shutdown','sigwrap_close','pthread_cancel','pthread_join','reset_hdisk_redir','racsessinfo_unregister_session','On_send_Vmedia_Session_Update']:
            calls.append({'call':n,'arg0':r0,'arg1':r1});ret(0);return
        if n=='setRedirectedMediaInfo':calls.append({'call':n,'device_type':r0,'media_type':word(r1),'instance':word(r1+4)});ret(0);return
        if n in ['Checkanyinstancerunning','IsLmediaRmediaRunning']:calls.append({'call':n,'result':0});ret(0);return
        if n=='__errno_location':ret(m.HEAP+0x20000);return
        raise AssertionError('Unapproved imported operation '+n+' '+hex(a))
    u.hook_add(U.UC_HOOK_CODE,hook)
    u.mem_write(0x198ec,P(FRAME));u.mem_write(FRAME,frame(last_opcode))
    u.mem_write(STATE,P(1));u.mem_write(STATE+0x130,P(1));u.mem_write(STATE+0x14,P(0))
    u.mem_write(STATE+0x144,P(0));u.mem_write(STATE+0x154,P(1));u.mem_write(STATE+0x1fc,P(1));u.mem_write(STATE+0x1ec,P(123))
    u.mem_write(GADGET,P(0));u.mem_write(GADGET+0x20,P(7));u.mem_write(FEATURES+0x1e4,P(1))
    u.reg_write(R.UC_ARM_REG_SP,m.STACK+0x18000);u.reg_write(R.UC_ARM_REG_LR,m.STOP)
    for reg,val in [(R.UC_ARM_REG_R4,0),(R.UC_ARM_REG_R5,0),(R.UC_ARM_REG_R6,0),
                    (R.UC_ARM_REG_R7,STATE),(R.UC_ARM_REG_R9,STATE),(R.UC_ARM_REG_R10,GADGET),(R.UC_ARM_REG_R11,0)]:u.reg_write(reg,val)
    u.emu_start(0x15828,m.STOP,count=100000)
    assert done
    return {'name':name,'transport':kind,'last_opcode_before_read':hex(last_opcode),
            'GetVMediaCfg_unbind_synthetic':unbind,'actual_entries':entries,'calls':calls,
            'final':{'slot_state':word(STATE),'nbd_slot':word(STATE+0x14),'gadget_slot':word(GADGET),
                     'socket':word(GADGET+0x20),'session_active':word(STATE+0x1fc)},
            'network_or_device_operations_executed':0}
def main():
    cases=[]
    for unbind in [False,True]:
        for kind in ['f3','f7','eof']:
            c=run(kind+('_unbind' if unbind else '_keep_udc'),kind,unbind)
            names=[x['call'] for x in c['calls']]
            if kind=='f3':
                assert c['final']['session_active']==1 and c['final']['socket']==7
                assert 'nbd_disconnect' not in names and 'hdisk_stop_boundary' not in names
            elif kind=='f7':
                assert c['final']['session_active']==0 and c['final']['socket']==0xffffffff
                assert c['final']['nbd_slot']==c['final']['gadget_slot']==0xffffffff
                assert names.count('nbd_disconnect')==names.count('hdisk_stop_boundary')==1
            else:
                assert c['final']['session_active']==0 and c['final']['socket']==0xffffffff
                assert c['final']['nbd_slot']==c['final']['gadget_slot']==0
                assert 'nbd_disconnect' not in names and 'hdisk_stop_boundary' not in names
            cases.append(c)
    # Last pending READ response is a different EOF branch: a synthetic NBD
    # response error causes explicit cleanup. This prevents overgeneralization.
    c=run('eof_pending_read_nbd_error', 'eof',False,0x28)
    names=[x['call'] for x in c['calls']]
    assert 'nbd_write_res' in names and 'nbd_disconnect' in names and 'hdisk_stop_boundary' in names
    assert c['final']['nbd_slot']==c['final']['gadget_slot']==0xffffffff
    cases.append(c)
    report={'status':'PASS','case_count':len(cases),'cases':cases,
            'source':{'path':str(m.IMAGE),'sha256':hashlib.sha256(m.IMAGE.read_bytes()).hexdigest()},
            'scope':'Actual original HD receive/dispatch/session cleanup instructions, entered after readiness checks; in-memory recv and audited session/gadget/NBD boundary stubs. No host I/O or target connection.',
            'conclusion':'F3 preserves the session. F7 explicitly clears gadget/NBD slots before common cleanup. TCP EOF after a lastF3 response can clear session/socket records while retaining gadget/NBD slot state; conditional UDC unbind does not clear those fields. EOF with a pending READ/error can clear them.',
            'limits':['All state and API return values are synthetic, not observed BMC memory.',
                      'A retained slot is not by itself proof of stale geometry, working backing device or current target cause.',
                      'Actual configfs, kernel NBD and session-database implementations are not executed by this fixture.']}
    (HERE/'disconnect_replay.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print(json.dumps({'status':'PASS','cases':len(cases),'case_names':[x['name'] for x in cases]}))
if __name__=='__main__':main()
