"""Execute original ARM receive+capacity bytes in synthetic memory only.

All imported I/O is trapped: recv uses an in-memory byte string, select returns
ready, logging is discarded. NBD initialization and gadget start are audited
scalar stubs; no kernel, device, subprocess or network operation is possible.
This verifies local parsing/state transitions, not real BMC attachment.
"""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'tools/pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import unicorn as U
from unicorn import arm_const as R

IMAGE=HERE/'backend/usr/local/bin/hdserverapp'
EXPECTED='3c1da9a7cc24930fe6115fd0d015b168b035219fd22243817123e1b4ae9f967b'
STOP=0x60000000;HEAP=0x70000000;STACK=0x71000000
STATE=0x2e340;FRAME=HEAP
P=lambda x:struct.pack('<I',x&0xffffffff)

def new_vm():
    raw=IMAGE.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
    assert raw[:6]==b'\x7fELF\x01\x01'
    u=U.Uc(U.UC_ARCH_ARM,U.UC_MODE_ARM|U.UC_MODE_LITTLE_ENDIAN)
    u.mem_map(0x10000,0x140000);u.mem_map(HEAP,0x40000);u.mem_map(STACK,0x20000);u.mem_map(STOP,0x1000)
    phoff=struct.unpack_from('<I',raw,28)[0];size,count=struct.unpack_from('<HH',raw,42)
    for i in range(count):
        typ,off,va,pa,fs,ms,flags,al=struct.unpack_from('<8I',raw,phoff+i*size)
        if typ==1:u.mem_write(va,raw[off:off+fs])
    return u

def make_frame(kind,op=0x25,status=0,tail=0):
    data={0x25:struct.pack('>II',32767,512),0x1a:b'\x03\0\0\0',0:b''}[op]
    n=61+len(data)+(32 if kind=='legacy' else 0)
    b=bytearray(n);b[:8]=b'IUSB    ';b[10]=0 if kind=='legacy' else 32
    struct.pack_into('<I',b,12,n-32);b[19]=128;b[41]=op
    struct.pack_into('<I',b,53,status);struct.pack_into('<I',b,57,len(data));b[61:61+len(data)]=data
    if kind=='legacy':b[61+len(data):]=bytes([tail])*32
    b[11]=(-sum(b))&255
    return bytes(b)

def run(name,raw,fragment=0x40000,nbd_rc=0,gadget_rc=0,do_process=True):
    u=new_vm();cursor=0;calls=[];phase='receive';actual=[]
    def word(p):return struct.unpack('<I',u.mem_read(p,4))[0]
    def ret(v):u.reg_write(R.UC_ARM_REG_R0,v&0xffffffff);u.reg_write(R.UC_ARM_REG_PC,u.reg_read(R.UC_ARM_REG_LR))
    thunks={int(x['address'],16):x['name'] for x in json.loads((HERE/'hdserver_decompile/function_inventory.json').read_text())['functions'] if x['thunk']}
    def hook(uc,addr,size,unused):
        nonlocal cursor
        if addr==STOP:uc.emu_stop();return
        if addr in (0x17054,0x16fd0,0x12e68,0x1780c,0x17824):actual.append(hex(addr))
        if addr==0x17dec:
            calls.append({'call':'hdisk_start_boundary','device_path_pointer':hex(uc.reg_read(R.UC_ARM_REG_R0)),
                          'removable':word(0x2e248),'readonly':word(0x2e24c),'result':gadget_rc})
            ret(gadget_rc);return
        if addr not in thunks:return
        n=thunks[addr]
        if n.startswith('IDBG_'):ret(0);return
        if n=='sigwrap_select':ret(1);return
        if n=='sigwrap_recv':
            dest=uc.reg_read(R.UC_ARM_REG_R1);want=uc.reg_read(R.UC_ARM_REG_R2)
            amount=min(want,fragment,len(raw)-cursor)
            if amount:uc.mem_write(dest,raw[cursor:cursor+amount])
            cursor+=amount;calls.append({'call':'synthetic_recv','requested':want,'returned':amount});ret(amount);return
        if n=='nbd_init':
            p=uc.reg_read(R.UC_ARM_REG_R0)
            calls.append({'call':'nbd_init_boundary','block_size':word(p+24),'block_size_high':word(p+28),
                          'blocks':word(p+32),'blocks_high':word(p+36),'readonly':word(p+68)&65535,'result':nbd_rc})
            if nbd_rc==0:uc.mem_write(p+20,P(0))
            ret(nbd_rc);return
        if n=='nbd_disconnect':calls.append({'call':n});ret(0);return
        if n=='__errno_location':ret(HEAP+0x20000);return
        raise AssertionError('Unapproved imported operation '+n+' at '+hex(addr))
    u.hook_add(U.UC_HOOK_CODE,hook)
    def call(addr,args):
        u.reg_write(R.UC_ARM_REG_SP,STACK+0x18000);u.reg_write(R.UC_ARM_REG_LR,STOP)
        for r,v in zip((R.UC_ARM_REG_R0,R.UC_ARM_REG_R1,R.UC_ARM_REG_R2,R.UC_ARM_REG_R3),args):u.reg_write(r,v)
        u.emu_start(addr,STOP+4,count=200000);assert u.reg_read(R.UC_ARM_REG_PC)==STOP
        return u.reg_read(R.UC_ARM_REG_R0)
    u.mem_write(0x198ec,P(FRAME));u.mem_write(STATE+0x130,P(1));u.mem_write(STATE+0x14,P(-1))
    u.mem_write(0x2e31c,P(HEAP+0x30000));u.mem_write(HEAP+0x30000,b'/dev/nbd0\0')
    receive_rc=call(0x17054,[7,FRAME,20]);process_rc=None
    if receive_rc==0 and do_process:
        process_rc=call(0x12e68,[0])
    return {'name':name,'frame_bytes':len(raw),'frame_sha256':hashlib.sha256(raw).hexdigest(),
            'receive_return':receive_rc,'process_return':process_rc,'consumed':cursor,'remaining':len(raw)-cursor,
            'final_state':word(STATE),'nbd_slot':word(STATE+20),'gadget_slot':word(0x2e200),
            'calls':calls,'actual_function_entries':actual}

def main():
    cases=[]
    for kind in ['legacy','canonical']:
        for chunk in [1,7,32,0x40000]:
            r=run(kind+'_chunk'+str(chunk),make_frame(kind),chunk)
            n=[x for x in r['calls'] if x['call']=='nbd_init_boundary'];g=[x for x in r['calls'] if x['call']=='hdisk_start_boundary']
            assert r['receive_return']==r['process_return']==0 and r['final_state']==1 and r['remaining']==0
            assert n==[{'call':'nbd_init_boundary','block_size':512,'block_size_high':0,'blocks':32768,'blocks_high':0,'readonly':0,'result':0}]
            assert len(g)==1 and g[0]['removable']==1 and g[0]['readonly']==0
            cases.append(r)
    r=run('legacy_nonzero_tail_does_not_change_capacity',make_frame('legacy',tail=0xa5));assert r['final_state']==1;cases.append(r)
    for kind in ['legacy','canonical']:
        r=run(kind+'_nbd_failure',make_frame(kind),nbd_rc=-1)
        assert r['final_state']==0 and r['process_return']==1 and not any(x['call']=='hdisk_start_boundary' for x in r['calls']);cases.append(r)
        r=run(kind+'_gadget_failure',make_frame(kind),gadget_rc=-1)
        assert r['final_state']==0 and r['process_return']==1 and r['nbd_slot']==0xffffffff and any(x['call']=='nbd_disconnect' for x in r['calls']);cases.append(r)
    r=run('truncated_payload',make_frame('legacy')[:-1]);assert r['receive_return']==1 and r['process_return'] is None;cases.append(r)
    r=run('payload_too_large',make_frame('legacy')[:12]+P(0x80000000)+make_frame('legacy')[16:]);assert r['receive_return']==1 and r['consumed']==32;cases.append(r)
    # Additional deliberate invalid metadata proves the inspected local routine
    # itself is not the policy validation layer. Never use this to relax client.
    r=run('error_status_not_checked_by_capacity_local_function',make_frame('legacy',status=0x200501));assert r['final_state']==1;cases.append(r)
    for kind in ['legacy','canonical']:
        b=bytearray(make_frame(kind));struct.pack_into('<I',b,57,0)
        r=run(kind+'_declared_data_len_not_checked_locally',bytes(b));assert r['final_state']==1;cases.append(r)
    out={'status':'PASS','scope':'original ARM bytes of receive and capacity dispatch with synthetic recv and NBD/gadget boundary stubs; no hardware/OS I/O',
         'source_sha256':EXPECTED,'function_addresses':['0x17054','0x16fd0','0x12e68','0x1780c','0x17824'],
         'case_count':len(cases),'cases':cases,
         'conclusion':'101-byte legacy and69-byte canonical capacity responses reach the same NBD/gadget boundary with512-byte blocks and32768 blocks. Tail bytes/headerLen difference does not explain the observed missing HD in this reviewed backend.',
         'limits':['NBD kernel behavior, filesystem/configfs writes and physical USB enumeration are not executed or proven.','Public1.1.57 backend image bytes have not been read back from BMC.','Fault injections are synthetic explanations for possible post-capacity silence, not observed backend failures.']}
    (HERE/'capacity_replay.json').write_text(json.dumps(out,indent=2),encoding='utf8');print(json.dumps({'status':'PASS','cases':len(cases)}))
if __name__=='__main__':main()
