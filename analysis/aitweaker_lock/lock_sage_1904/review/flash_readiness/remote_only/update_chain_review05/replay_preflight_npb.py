"""Additional bounded native helper, wrapper and NPB data-flow replays.

All file descriptors are virtual. NPB lengths are deliberately bounded fixtures;
the exact original table is parsed separately, not falsely called fully replayed.
"""
from pathlib import Path
import json,struct,sys
sys.dont_write_bytecode=True
from replay_chain import VM,HERE,BASE,ROOT,HALT,UC_ARM_REG_SP,sha,require
class FileVM(VM):
    def external(self,name,args):
        x,y,z,w=args
        if name=='access':return 0 if self.text(x) in self.files else 0xffffffff
        if name=='ftell':return self.handles[x]['position']
        if name=='rewind':self.handles[x]['position']=0;return 0
        if name=='fseek':
            f=self.handles[x];size=len(self.files[f['path']]);f['position']=(0 if z==0 else f['position'] if z==1 else size)+y;return 0
        if name=='dlopen':require(self.text(x)=='/usr/local/lib/libpdkapp.so','dynamiclib');return 0x123
        if name=='dlsym':require(x==0x123 and self.text(y)=='PDK_VerifyBiosSignature','dynamicmethod');return HALT+4
        if name=='dlclose':require(x==0x123,'normal close');return 0
        if name=='PDK_VERDICT_STUB':return self.verdict
        return super().external(name,args)
def main():
    rows=[];names=[]
    def check(ok,name):require(ok,name);names.append(name)
    cap=ROOT/'analysis/aitweaker_lock/official_W790E_SAGE_SE_1904/W790E_SAGE_SE_1904/Pro-WS-W790E-SAGE-SE-ASUS-1904.CAP'
    data=cap.read_bytes();check(sha(data)=='aba26bf927de341f1859dd6b5f35645564d5aea104fb26bcc7b5a98bcd96b0b3','originalCAP_pin')
    for case,files,expected in [('fullcap_signature_path',{'/var/biossig.bin':data},0),
                                ('fullcap_ignores_stale_payload',{'/var/biossig.bin':data,'/var/bios.bin':b'STALE'},0),
                                ('split_header_payload',{'/var/biossig.bin':data[:4096],'/var/bios.bin':data[4096:]},0),
                                ('payload_only_missing_header',{'/var/bios.bin':data[4096:]},0xffffffff),
                                ('missing_files',{},0xffffffff)]:
        v=FileVM(['pdk']);v.files=files.copy();out=v.alloc(4);size=v.alloc(4)
        result=v.run('pdk','read_file_append',[v.stringptr('/var/biossig.bin'),v.stringptr('/var/bios.bin'),out,size])
        check(result==expected,case+'_status')
        row={'case':case,'status':hex(result)}
        if result==0:
            n=v.u32(size);check(n==len(data),case+'_size');got=sha(bytes(v.uc.mem_read(v.u32(out),n)))
            check(got==sha(data),case+'_exact_originalCAP_bytes');row['reconstructed_sha256']=got
        check(not any(c['import']=='fopen' and 'w' in c.get('mode','') for c in v.calls),case+'_no_target_file_writes')
        rows.append({**row,'boundary':'Actual read_file_append; only RAM-backed libc file/allocation imports. No signature replay.',**v.summary()})
    for verdict in (0,1):
        v=FileVM(['bios']);v.verdict=verdict;v.plt[HALT+4]=('bios','PDK_VERDICT_STUB')
        result=v.run('bios','verify_bios_signature',[11])
        check(result==0,'wrapper_send_return_'+str(verdict));check(v.response[0]==(0 if verdict==0 else 255),'wrapper_status_'+str(verdict))
        check(not any(c['import'] in ('ActiveHostSPIDriver','SwitchGPIO','pthread_create','BiosConfiguration') for c in v.calls),'wrapper_no_SPI_or_update_state_'+str(verdict))
        rows.append({'case':'wrapper_verdict_'+str(verdict),'boundary':'Actual verify_bios_signature, PDK verdict is an explicit stub; known original four crypto cases are separately bound.',**v.summary()})
    official=json.loads((HERE/'api_and_ranges.json').read_text())['original_BOOTEFi_headers'][0]
    original_header=bytes.fromhex(official['bytes'])
    table=struct.pack('<BII',1,0,0x10020)+struct.pack('<BII',2,0x3110000,16)
    for case in ('normal_preserve','zero_current_version_skips','zero_uploaded_count_skips','readback_diff_fails','source_read_failure_not_checked'):
        v=FileVM(['pdk']);head=bytearray(original_header)
        if case=='zero_current_version_skips':head[12:14]=b'\0\0'
        current=v.alloc(0xd8,bytes(head)+bytes(0xd8-len(head)))
        uploaded=v.alloc(0xd8,original_header+bytes(0xd8-len(original_header)));t=v.alloc(len(table),table)
        v.w32(uploaded+0xbb,0 if case=='zero_uploaded_count_skips' else 2);v.w32(uploaded+0xcb,t)
        positions={7:0,8:0};staged={};events=[];source_reads=0;failed_source=0
        def seek(a):
            fd,off,whence,_=a;require(fd in (7,8) and whence==0,'NPB seek');positions[fd]=off;return off
        def read(a):
            nonlocal source_reads,failed_source
            fd,dest,n,_=a;require(fd in (7,8) and n<=0x10000,'NPB read');off=positions[fd]
            events.append({'operation':'read','fd':fd,'offset':hex(off),'bytes':n})
            if fd==7:
                source_reads+=1
                if case=='source_read_failure_not_checked' and source_reads==1:
                    failed_source+=1;events[-1]['result']='-1';return 0xffffffff
                b=bytes([0x31+(off>>16)%32])*n
            else:
                b=staged[(off,n)]
                if case=='readback_diff_fails':b=bytes([b[0]^1])+b[1:]
            v.uc.mem_write(dest,b);positions[fd]+=n;return n
        def write(a):
            fd,src,n,_=a;require(fd==8 and n<=0x10000,'NPB writes only staged file')
            off=positions[fd];staged[(off,n)]=bytes(v.uc.mem_read(src,n));positions[fd]+=n
            events.append({'operation':'write','fd':fd,'offset':hex(off),'bytes':n,'sha256':sha(staged[(off,n)])});return n
        v.overrides.update(lseek=seek,sigwrap_read=read,sigwrap_write=write)
        result=v.run('pdk','PDK_ASUSBIOSConfiguration',[7,8,0,current],struct.pack('<I',uploaded))
        expected=0xffffffff if case=='readback_diff_fails' else 0
        check(result==expected,case+'_native_return')
        writes=[e for e in events if e['operation']=='write']
        check(len(writes)==(0 if 'skips' in case else 3),case+'_writes')
        if 'skips' not in case:
            check([(e['offset'],e['bytes']) for e in writes]==[('0x0',65536),('0x10000',32),('0x3110000',16)],case+'_range_chunks')
        if case=='source_read_failure_not_checked':
            check(failed_source==1 and staged[(0,0x10000)]==bytes(0x10000),'unchecked_failed_source_copies_allocator_bytes_and_returns_success')
        rows.append({'case':case,'result':hex(result),'events':events,'failed_source_reads':failed_source,
                     'boundary':'Actual PDK_ASUSBIOSConfiguration, original-header fixture, two synthetic bounded NPB records; RAM-backed MTD/file imports. This is not a live preservation test or the full48MiB table loop.',**v.summary()})
    report={'status':'PASS_COUNTEREXAMPLE_CONFIRMED','cases':len(rows),'checks':len(names),'check_names':names,'cases_detail':rows,
            'inputs':{'script_sha256':sha(Path(__file__).read_bytes()),'harness_sha256':sha((HERE/'replay_chain.py').read_bytes()),'originalCAP_sha256':sha(data),'api_ranges_sha256':sha((HERE/'api_and_ranges.json').read_bytes())},
            'key_result':'The normal preservation worker copies requested source data to the staged file and compares readback, but does not check source sigwrap_read return values. A modeled source-read failure leaves allocated bytes which are copied and compare successfully; native function returns0. This limits a fail-safe claim based only on the NPB table.',
            'scope':{'network':0,'device_access':0,'firmware_writes':0,'CAP_created_or_uploaded':0,'new_crypto_verification':0}}
    p=HERE/'preflight_npb_replay.json';p.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'status':report['status'],'cases':len(rows),'checks':len(names),'sha256':sha(p.read_bytes()),'path':str(p)}))
if __name__=='__main__':main()
