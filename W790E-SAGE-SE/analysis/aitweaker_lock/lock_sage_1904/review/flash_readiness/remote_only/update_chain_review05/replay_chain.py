"""Bounded actual ARM-instruction replays with closed virtual I/O only.

Nothing calls BMC, an operating-system device, a flash ioctl, or native ARM code.
No CAP/key generation or input mutation. Imported file/dictionary/IPC/hardware
calls are explicit model boundaries; host helper code performs the control flow.
"""
from pathlib import Path
import hashlib,json,struct,sys
sys.dont_write_bytecode=True
from inspect_chain import HERE,BASE,ROOT,Elf32,sha,disassemble
sys.path.insert(0,str(ROOT/'tools/pydeps'))
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
from unicorn.arm_const import *
REGS=(UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)
FEATURE='CONFIG_SPX_FEATURE_SIGNED_HASHED_IMAGE_SUPPORT'
LIB=BASE/'bmc_backend/5308416/usr/local/lib'
SOURCES={'feature':LIB/'libfeaturedefine.so.13.6.6',
         'ini':HERE/'official_inputs/5308416/usr/local/lib/libiniparser.so.13.2.0',
         'bios':LIB/'libcompamibios.so.13.0.1',
         'host':LIB/'libhosthelper.so.13.0.1',
         'pdk':LIB/'libpdkapp.so.13.2.4'}
PINS={'feature':'7feb920b15f7ef50cb85e0e0c74c4cac2301abcde301183824d9aa16cc475f83',
      'bios':'fa6a4f658e6b59756aeb8fb0a4066f4be0502c3c2841d0dff71975cce6b71187',
      'pdk':'35459aed01642e815001dc0e319f25ac79ae3ed72607d0895452513ebe38b567'}
STACK=0x08000000;HALT=0x09000000;GLOBAL=0x06000000;HEAP=0x10000000
def require(x,msg):
    if not x:raise AssertionError(msg)
class VM:
    def __init__(self,labels):
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.modules={};self.plt={};self.globals={};self.global_next=GLOBAL
        self.uc.mem_map(GLOBAL,0x100000);self.uc.mem_map(HEAP,0x6000000)
        self.uc.mem_map(STACK,0x40000);self.uc.mem_map(HALT,4096)
        self.uc.mem_write(HALT,bytes.fromhex('1eff2fe1'))
        self.heap=HEAP;self.files={};self.handles={};self.next_handle=0x06080000
        self.calls=[];self.instructions=0;self.error=None;self.returned=False;self.native=[];self.overrides={}
        self.dictionary={};self.loaded_dictionary={};self.dhandle=0x06090000
        self.fail_create=False;self.resident_result=0;self.file_size=0x4000000;self.file_size_result=0;self.configuration_result=0
        self.response=None;self.worker=None;self.spi_blocks=[];self.erases=[];self.writes=[];self.seek=[];self.device_data=bytes(0x10000);self.spi_fail_read=False
        self.resident_calls=0;self.configuration_calls=0
        for i,label in enumerate(labels):self.map(label,0x00100000*(i+1))
        self.uc.hook_add(UC_HOOK_CODE,self.code);self.uc.hook_add(UC_HOOK_MEM_INVALID,self.invalid)
    def alloc(self,n,data=None):
        p=self.heap;self.heap=(p+max(n,16)+15)&~15;require(self.heap<HEAP+0x6000000,'heap bound')
        if data is not None:self.uc.mem_write(p,data)
        return p
    def stringptr(self,s):return self.alloc(len(s)+1,s.encode()+b'\0')
    def text(self,p,limit=8192):
        out=bytearray()
        while len(out)<limit:
            n=min(256,limit-len(out),4096-((p+len(out))&4095))
            b=bytes(self.uc.mem_read(p+len(out),n));k=b.find(b'\0')
            if k>=0:return (out+b[:k]).decode('ascii')
            out.extend(b)
        raise AssertionError('cstring bound')
    def u32(self,p):return struct.unpack('<I',self.uc.mem_read(p,4))[0]
    def w32(self,p,v):self.uc.mem_write(p,struct.pack('<I',v&0xffffffff))
    def glob(self,name):
        if name not in self.globals:self.globals[name]=self.global_next;self.global_next+=0x4000
        require(self.global_next<GLOBAL+0x80000,'global bound')
        return self.globals[name]
    def map(self,label,bias):
        e=Elf32(SOURCES[label]);require(not PINS.get(label) or sha(e.data)==PINS[label],'source pin '+label)
        phoff=struct.unpack_from('<I',e.data,28)[0];phsz,phn=struct.unpack_from('<HH',e.data,42)
        loads=[struct.unpack_from('<8I',e.data,phoff+i*phsz) for i in range(phn)];loads=[p for p in loads if p[0]==1]
        maximum=max(p[2]+p[5] for p in loads);self.uc.mem_map(bias,(maximum+4095)&~4095)
        for _,off,va,_,fs,_,_,_ in loads:self.uc.mem_write(bias+va,e.data[off:off+fs])
        for va,r in e.relocations.items():
            addend=self.u32(bias+va)
            if r['type']==23:self.w32(bias+va,addend+bias)
            elif r['type']==2:self.w32(bias+va,addend+(bias+r['symbol_va'] if r['symbol_defined'] else self.glob(r['symbol'])))
            elif r['type']==21:self.w32(bias+va,bias+r['symbol_va'] if r['symbol_defined'] else self.glob(r['symbol']))
        self.modules[label]={'elf':e,'bias':bias,'functions':{s['name']:s for s in e.symbols if s['section_index'] and (s['info']&15)==2}}
        self.plt.update({bias+p:(label,n) for p,n in e.plt.items()})
    def addr(self,label,name):return self.modules[label]['bias']+self.modules[label]['functions'][name]['va']
    def invalid(self,uc,access,address,size,value,user):
        self.error=f'invalid memory {access} {address:x}+{size}';return False
    def code(self,uc,pc,size,user):
        try:
            self.instructions+=1
            if pc==HALT:self.returned=True;uc.emu_stop();return
            if pc in self.plt:
                label,name=self.plt[pc];args=[uc.reg_read(x) for x in REGS];caller=uc.reg_read(UC_ARM_REG_LR)-4
                self.calls.append({'library':label,'import':name,'caller_va':hex(caller-self.modules[label]['bias'])})
                # Link these approved imports to their real ARM implementations.
                link={'IniLoadFile':('ini','IniLoadFile'),'IsFeatureEnabled':('feature','IsFeatureEnabled')}
                if name in link and link[name][0] in self.modules:
                    uc.reg_write(UC_ARM_REG_PC,self.addr(*link[name]));return
                if name in self.overrides:r=self.overrides[name](args)
                else:r=self.external(name,args)
                uc.reg_write(UC_ARM_REG_R0,r&0xffffffff);uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR));return
            require(any(m['bias']+m['elf'].byname['.text']['va']<=pc<m['bias']+m['elf'].byname['.text']['va']+m['elf'].byname['.text']['size'] for m in self.modules.values()),f'outside approved code {pc:x}')
        except Exception as exc:self.error=type(exc).__name__+': '+str(exc);uc.emu_stop()
    def external(self,name,a):
        x,y,z,w=a
        if name=='memset':self.uc.mem_write(x,bytes([y&255])*z);return x
        if name=='memcpy':self.uc.mem_write(x,bytes(self.uc.mem_read(y,z)));return x
        if name=='strlen':return len(self.text(x))
        if name=='strchr':
            b=self.text(x).encode();i=b.find(bytes([y&255]));return x+i if i>=0 else 0
        if name=='strncmp':
            b=self.text(x).encode()+b'\0';c=self.text(y).encode()+b'\0'
            b=b[:z];c=c[:z];return (b>c)-(b<c)
        if name=='snprintf':
            fmt=self.text(z);require(fmt=='%s:%s','only feature snprintf')
            last=self.u32(self.uc.reg_read(UC_ARM_REG_SP));b=(self.text(w)+':'+self.text(last)).encode()
            self.uc.mem_write(x,b[:y-1]+b'\0');return len(b)
        if name in ('IDBG_LINUXAPP_DbgOut','IDBG_LINUXAPP_Runtime_DbgOut','printf','puts'):return 0
        if name=='fopen':
            path,mode=self.text(x),self.text(y);self.calls[-1].update(path=path,mode=mode)
            if 'w' in mode:
                if self.fail_create:return 0
                self.files[path]=b''
            elif path not in self.files:return 0
            self.next_handle+=16;self.handles[self.next_handle]={'path':path,'position':0};return self.next_handle
        if name=='fclose':return 0
        if name=='feof':
            f=self.handles[x];return int(f['position']>=len(self.files[f['path']]))
        if name=='__isoc99_fscanf':
            require(self.text(y)=='%256s','fscanf scope');f=self.handles[x];b=self.files[f['path']];tail=b[f['position']:]
            fields=tail.split(None,1)
            if not fields:f['position']=len(b);return 0xffffffff
            token=fields[0];require(len(token)<=256,'bounded token');i=tail.find(token);f['position']+=i+len(token)
            self.uc.mem_write(z,token+b'\0');return 1
        if name=='iniparser_load':
            require(self.text(x)=='/var/tmp/libfeature','INI path');self.loaded_dictionary=dict(self.dictionary);return self.dhandle
        if name=='iniparser_add_entry':
            require(x==self.dhandle,'dict handle');k=self.text(y)+':'+self.text(z);self.loaded_dictionary[k.lower()]=self.text(w);return 0
        if name=='iniparser_getstring':
            require(x==self.dhandle,'dict handle');v=self.loaded_dictionary.get(self.text(y).lower())
            return z if v is None else self.stringptr(v)
        if name=='get_bios_file_size':self.w32(x,self.file_size);return self.file_size_result
        if name=='VerifyImageSign':
            require(x==1 and self.text(y)=='/var/bios.bin' and z==0,'resident args');self.resident_calls+=1;return self.resident_result
        if name=='GetHashLength':return 1
        if name=='BiosConfiguration':self.configuration_calls+=1;return self.configuration_result
        if name=='pthread_create':
            self.worker={'entry':hex(z),'arguments':list(struct.unpack('<4I',self.uc.mem_read(w,16)))};return 0
        if name=='ActiveHostSPIDriver':self.calls[-1]['argument']=x;return 0
        if name=='send_compmngr_response':self.response=list(struct.unpack('<IHH',self.uc.mem_read(x+4,8)));return 0
        if name=='malloc':return self.alloc(x)
        if name=='free':return 0
        if name=='fread':
            f=self.handles[w];n=y*z;b=self.files[f['path']]
            if isinstance(b,int):available=max(0,min(n,b-f['position']));data=b'\xA5'*available
            else:data=b[f['position']:f['position']+n]
            self.uc.mem_write(x,data);f['position']+=len(data);return len(data)//y if y else 0
        if name=='spi_write_erase_block':self.spi_blocks.append(z);return 0
        if name=='lseek':self.seek.append({'fd':x,'offset':y,'whence':z});self.device_position=y;return y
        if name=='sigwrap_read':
            if self.spi_fail_read:return 0xffffffff
            require(z<=len(self.device_data),'bounded synthetic device');self.uc.mem_write(y,self.device_data[:z]);return z
        if name=='sigwrap_write':self.writes.append({'fd':x,'offset':self.device_position,'size':z,'sha256':sha(bytes(self.uc.mem_read(y,z)))});return z
        if name=='ioctl':self.erases.append({'fd':x,'request':hex(y),'start':self.u32(z),'length':self.u32(z+4)});return 0
        raise AssertionError('unmodeled import '+name)
    def run(self,label,name,args=(),stack=b'',limit=5000000):
        for r in REGS:self.uc.reg_write(r,0)
        for r,a in zip(REGS,args):self.uc.reg_write(r,a&0xffffffff)
        sp=STACK+0x3f000;self.uc.mem_write(sp,b'\0'*0x800);self.uc.mem_write(sp,stack)
        self.uc.reg_write(UC_ARM_REG_SP,sp);self.uc.reg_write(UC_ARM_REG_LR,HALT)
        self.error=None;self.returned=False
        self.uc.emu_start(self.addr(label,name),0,count=limit)
        require(self.error is None,self.error);require(self.returned,'instruction limit or no return')
        return self.uc.reg_read(UC_ARM_REG_R0)
    def summary(self):return {'instructions':self.instructions,'calls':self.calls,'resident_calls':self.resident_calls,'configuration_calls':self.configuration_calls,'worker':self.worker,'response':self.response,'erases':self.erases,'writes':self.writes,'spi_block_calls':len(self.spi_blocks)}
def main():
    rows=[];checks=[]
    def check(ok,name):require(ok,name);checks.append(name)
    core=(BASE/'bmc_backend/5308416/etc/core_features').read_bytes()
    matrix=[('official_absent',None,core,False,0),('INI_enabled','1',core,False,1),('INI_zero','0',core,False,0),('INI_false_word','false',core,False,1),('INI_empty','',core,False,0),('INI_double_zero','00',core,False,1),('core_overrides_zero','1',core+('\n'+FEATURE+'=0\n').encode(),False,0),('core_bare_enables','0',core+('\n'+FEATURE+'\n').encode(),False,1),('missing_INI_created',None,core,True,0)]
    for name,value,content,missing,expected in matrix:
        v=VM(['feature','ini']);v.files={'/etc/core_features':content}
        if not missing:v.files['/var/tmp/libfeature']=b''
        if value is not None:v.dictionary['core_features:'+FEATURE.lower()]=value
        result=v.run('feature','IsFeatureEnabled',[v.stringptr(FEATURE)])
        check(result==expected,name+'_value')
        writes=[c for c in v.calls if c['import']=='fopen' and c.get('mode')=='wb']
        check(bool(writes)==missing,name+'_virtual_create_boundary')
        rows.append({'case':name,'expected':expected,'actual':result,'boundary':'Native IniLoadFile and IsFeatureEnabled; libc/INI dictionary parser imports modeled.',**v.summary()})
    v=VM(['feature','ini']);v.files={'/etc/core_features':core};v.fail_create=True
    check(v.run('feature','IsFeatureEnabled',[v.stringptr(FEATURE)])==0,'INI_create_failure_false')
    rows.append({'case':'INI_create_failure',**v.summary()})
    v=VM(['feature','ini']);v.files={'/etc/core_features':core,'/var/tmp/libfeature':b''};ptr=v.stringptr(FEATURE)
    check(v.run('feature','IsFeatureEnabled',[ptr])==0,'cached_first_zero')
    before=len([c for c in v.calls if c['import']=='fopen'])
    v.dictionary['core_features:'+FEATURE.lower()]='1';v.files['/etc/core_features']=core+('\n'+FEATURE+'\n').encode()
    check(v.run('feature','IsFeatureEnabled',[ptr])==0,'cache_does_not_reload_changed_files')
    check(len([c for c in v.calls if c['import']=='fopen'])==before,'cache_no_reopen')
    rows.append({'case':'process_cache_is_snapshot',**v.summary()})
    for value in [None,'1']:
        v=VM(['feature','ini']);v.files={'/etc/core_features':core,'/var/tmp/libfeature':b''}
        if value:v.dictionary['core_features:'+FEATURE.lower()]=value
        p=v.alloc(0x1000);v.run('feature','RetrieveCoreFeatures',[p]);actual=v.u32(p+0x34)
        check(actual==int(value is not None),'native_core_struct_map_'+str(value))
        rows.append({'case':'RetrieveCoreFeatures_'+str(value),'actual_offset34':actual,**v.summary()})
    for flag,resident in [(0,1),(1,1),(1,0),(2,1),(0xffffffff,1)]:
        v=VM(['bios']);v.w32(v.glob('g_corefeatures')+0x34,flag)
        e=v.modules['bios']['elf'];rel=e.relocations[0x3f04];uidname=rel['symbol'];uid=0x13579
        v.w32(v.glob(uidname),uid);v.resident_result=resident
        message=struct.pack('<HIIII',16,uid,0,0x4000000,0)
        r2,r3=struct.unpack('<II',message[:8]);v.run('bios','bios_start_update',[0x20003,123,r2,r3],message[8:])
        check(v.resident_calls==int(flag==1),'resident_called_only_exact_one_'+str(flag)+'_'+str(resident))
        failed=flag==1 and resident!=0
        check((v.worker is None)==failed,'resident_failure_stops_worker_'+str(flag)+'_'+str(resident))
        check(v.configuration_calls==int(not failed),'resident_before_configuration_'+str(flag)+'_'+str(resident))
        check(v.response[0]==(255 if failed else 0),'response_'+str(flag)+'_'+str(resident))
        if not failed:check(v.worker['arguments'][:3]==[0,0x4000000,0],'worker_extent_'+str(flag)+'_'+str(resident))
        rows.append({'case':f'start_update_flag_{flag}_resident_{resident}','boundary':'VerifyImageSign/BiosConfiguration/thread/driver/response imports observed as stubs; no crypto or thread executed.',**v.summary()})
    v=VM(['host']);e=v.modules['host']['elf'];r=e.literal(0x1838);gp=v.modules['host']['bias']+int(r['target_elf_va'],16) if r.get('target_elf_va') else v.glob(r['relocation']['symbol'])
    v.w32(gp+0x1c,0x10000);v.files['/var/bios.bin']=0x4000000
    p=v.alloc(4);result=v.run('host','flash_bios_image',[7,v.stringptr('/var/bios.bin'),0,0x4000000],struct.pack('<I',p))
    check(result==0,'native_flash_loop_success')
    check(v.spi_blocks==list(range(0,0x4000000,0x10000)),'native_flash_loop_all_1024_64KiB_blocks')
    rows.append({'case':'whole_64MiB_loop','first':hex(v.spi_blocks[0]),'last':hex(v.spi_blocks[-1]),'block_offsets_sha256':sha(b''.join(struct.pack('<I',x) for x in v.spi_blocks)),'boundary':'Actual flash_bios_image loop; spi_write_erase_block intercepted and never executes for this case.',**v.summary()})
    for mode in ['same','different_first','different_last','short_read']:
        v=VM(['host']);e=v.modules['host']['elf'];r=e.literal(0x1678);gp=v.modules['host']['bias']+int(r['target_elf_va'],16) if r.get('target_elf_va') else v.glob(r['relocation']['symbol'])
        n=0x10000;v.w32(gp+0x1c,n);v.device_data=b'\x5A'*n;new=bytearray(v.device_data)
        if mode=='different_first':new[0]^=1
        if mode=='different_last':new[-1]^=1
        if mode=='short_read':v.spi_fail_read=True
        result=v.run('host','spi_write_erase_block',[7,v.alloc(n,bytes(new)),0x3000000])
        changed=mode.startswith('different')
        check(len(v.erases)==int(changed),'block_erase_'+mode);check(len(v.writes)==int(changed),'block_write_'+mode)
        check(result==(0xffffffff if mode=='short_read' else 0),'block_result_'+mode)
        if changed:check(v.erases==[{'fd':7,'request':'0x40084d02','start':0x3000000,'length':n}],'MEMERASE_extent_'+mode)
        rows.append({'case':'native_spi_block_'+mode,'boundary':'Actual spi_write_erase_block compare/branch; only RAM-backed read and recorded ioctl/write imports.',**v.summary()})
    report={'status':'PASS','checks':len(checks),'cases':len(rows),'check_names':checks,'cases_detail':rows,
            'source':{'script':str(Path(__file__)),'sha256':sha(Path(__file__).read_bytes()),'inputs':{k:{'path':str(p),'sha256':sha(p.read_bytes())} for k,p in SOURCES.items()}},
            'limits':['Import models are explicit; this is not full libc/iniparser/crypto/REST/auth or kernel driver emulation.','No runtime BMC values, live backend hashes or hardware acceptance is inferred.','Erase geometry 64KiB is a synthetic loop/compare fixture, not measured BMC MTD geometry.','Known four CAP signature cases are reused, not repeated or expanded here.'],
            'side_effects':{'network':0,'BMC_connections':0,'device_reads':0,'device_writes':0,'host_file_opens_from_target':0,'CAP_generated_or_uploaded':0,'firmware_modified':0}}
    path=HERE/'native_replay.json';path.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'status':'PASS','checks':len(checks),'cases':len(rows),'path':str(path),'sha256':sha(path.read_bytes())}))
if __name__=='__main__':main()
