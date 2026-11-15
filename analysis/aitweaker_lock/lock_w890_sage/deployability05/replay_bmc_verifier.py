"""Execute the original ARM verifier in Unicorn with explicit host-service models.

Only the original verifier and PLT entry instructions may execute. File I/O is
an in-memory fixture. OpenSSL imports are independent RSA-PSS/SHA256 oracles,
not success constants. No BMC request, target OS, flash device or updater runs.
"""
from pathlib import Path
import hashlib,json,struct,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import unicorn
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
from elf32 import ELF32

IMAGE=HERE/'backend_inputs/libpdkapp.so.13.19.0'
CAP=ROOT/'analysis/workstation_20261008/W890_SAGE_0603/Pro-WS-W890E-SAGE-SE-ASUS-0603.CAP'
BASE=0x10000;FIXTURE=0x10000000;STUB=0x800000;STACK=0x900000;END=0x700000

def sha(b):return hashlib.sha256(b).hexdigest()
def bind(p):return {'path':str(p.resolve()),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}

def pss_verify(n,e,signature,digest):
    width=(n.bit_length()+7)//8
    if n.bit_length()!=2048 or e!=65537 or len(signature)!=width:return False
    s=int.from_bytes(signature,'big')
    if s>=n:return False
    em=pow(s,e,n).to_bytes(width,'big')
    if em[-1]!=0xbc or em[0]&128:return False
    h=em[-33:-1];masked=em[:-33]
    mask=b''.join(hashlib.sha256(h+i.to_bytes(4,'big')).digest() for i in range((len(masked)+31)//32))[:len(masked)]
    db=bytearray(x^y for x,y in zip(masked,mask));db[0]&=0x7f
    pos=next((i for i,x in enumerate(db) if x),None)
    if pos is None or db[pos]!=1:return False
    return hashlib.sha256(bytes(8)+digest+bytes(db[pos+1:])).digest()==h

class Replay:
    def __init__(self,capsule,file_failure=False):
        self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.cap=bytes(capsule);self.file_failure=file_failure
        self.objects={};self.objnext=STUB+0x8000;self.events=[];self.chunks=[];self.finals=[];self.steps=0
        data=IMAGE.read_bytes();elf=ELF32(data)
        self.uc.mem_map(BASE,0x20000);self.uc.mem_map(STUB,0x10000);self.uc.mem_map(STACK,0x20000);self.uc.mem_map(END,0x1000)
        self.uc.mem_map(FIXTURE,(len(capsule)+4095)&~4095);self.uc.mem_write(FIXTURE,self.cap)
        for typ,off,vaddr,phys,filesz,memsz,flags,align in elf.programs:
            if typ==1:self.uc.mem_write(BASE+vaddr,elf.read(off,filesz))
        self.external={};self.extnext=STUB+0x100
        for section in elf.sections:
            if section['type']!=9:continue
            syms=elf.symbols[section['link']]
            for off in range(section['offset'],section['offset']+section['size'],8):
                target,info=struct.unpack('<II',elf.read(off,8));kind=info&255;sym=syms[info>>8]
                address=BASE+target;addend=self.u32(address)
                if kind==23:value=BASE+addend
                elif kind in (2,21,22):
                    if sym['section']:value=BASE+sym['value']
                    else:
                        name=sym['name']
                        if name not in self.external:self.external[name]=self.extnext;self.extnext+=16
                        value=self.external[name]
                    if kind==2:value+=addend
                elif kind==0:continue
                else:raise ValueError('Unmodeled ELF relocation '+str(kind))
                self.w32(address,value)
        self.w32(self.external['__stack_chk_guard'],0x19a79d52)
        analysis=json.loads((HERE/'ghidra_backend/pdkapp/analysis.json').read_text())
        self.plt={int(x['address'],16):x['name'] for x in analysis['functions'] if x['thunk']}
        self.uc.reg_write(UC_ARM_REG_SP,STACK+0x1f000);self.uc.reg_write(UC_ARM_REG_LR,END)
        self.uc.hook_add(UC_HOOK_CODE,self.hook)
    def u32(self,p):return struct.unpack('<I',self.uc.mem_read(p,4))[0]
    def w32(self,p,v):self.uc.mem_write(p,struct.pack('<I',v&0xffffffff))
    def args(self):return [self.uc.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
    def obj(self,value):
        p=self.objnext;self.objnext+=16
        if self.objnext>=STUB+0xf000:raise ValueError('Object fixture bound')
        self.objects[p]=value;return p
    def cstr(self,p):
        b=bytes(self.uc.mem_read(p,512));return b.split(b'\0',1)[0].decode('ascii','replace')
    def ret(self,v=0):
        self.uc.reg_write(UC_ARM_REG_R0,v&0xffffffff);self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))
    def hook(self,uc,address,size,user):
        self.steps+=1
        if address==END:uc.emu_stop();return
        if address not in self.plt:
            if not 0x129b0<=address<0x12d7c:raise ValueError('Unexpected native execution '+hex(address))
            return
        name=self.plt[address];a,b,c,d=self.args();value=0
        if name=='read_file_append':
            assert [self.cstr(a),self.cstr(b)]==['/var/biossig.bin','/var/bios.bin']
            self.w32(c,0 if self.file_failure else FIXTURE);self.w32(d,0 if self.file_failure else len(self.cap))
            self.events.append({'service':'file_fixture','bytes':0 if self.file_failure else len(self.cap)})
            value=-1 if self.file_failure else 0
        elif name=='RSA_new':value=self.obj({})
        elif name=='BN_bin2bn':value=self.obj(int.from_bytes(self.uc.mem_read(a,b),'big'))
        elif name=='RSA_set0_key':self.objects[a].update(n=self.objects[b],e=self.objects[c]);value=1
        elif name=='EVP_PKEY_new':value=self.obj({})
        elif name=='EVP_PKEY_assign':assert b==6;self.objects[a]['rsa']=self.objects[c];value=1
        elif name=='EVP_PKEY_CTX_new':value=self.obj({'key':a})
        elif name=='EVP_MD_CTX_new':value=self.obj({})
        elif name=='EVP_sha256':value=self.obj({'algorithm':'sha256'})
        elif name=='EVP_DigestVerifyInit':
            key=self.u32(self.uc.reg_read(UC_ARM_REG_SP));assert d==0 and self.objects[c]['algorithm']=='sha256'
            self.objects[a]={'key':self.objects[key]['rsa'],'hash':hashlib.sha256(),'ranges':[]}
            self.w32(b,self.obj({'ctx':a}));value=1
        elif name=='EVP_PKEY_CTX_set_rsa_padding':assert b==6;self.objects[self.objects[a]['ctx']]['pss']=True;value=1
        elif name=='EVP_DigestVerifyUpdate':
            offset=b-FIXTURE
            if not 0<=offset<=len(self.cap) or c>len(self.cap)-offset:raise ValueError('Native hash span outside input')
            ctx=self.objects[a];ctx['hash'].update(bytes(self.uc.mem_read(b,c)));ctx['ranges'].append({'offset':offset,'bytes':c});value=1
        elif name=='EVP_DigestVerifyFinal':
            ctx=self.objects[a];assert ctx.get('pss')
            digest=ctx['hash'].digest();rsa=ctx['key']
            valid=pss_verify(rsa['n'],rsa['e'],bytes(self.uc.mem_read(b,c)),digest)
            self.finals.append({'valid':valid,'digest':digest.hex(),'ranges':ctx['ranges'],
                                'public_modulus_sha256':sha(rsa['n'].to_bytes(256,'big')),'signature_offset':b-FIXTURE})
            value=int(valid)
        elif name in ('EVP_MD_CTX_free','free'):pass
        elif name in ('printf','puts'):self.events.append({'service':name,'format':self.cstr(a)})
        elif name=='unlink':assert self.cstr(a)=='/var/biossig.bin';self.events.append({'service':'modeled_unlink','path':'/var/biossig.bin'})
        else:raise ValueError('Unmodeled import '+name)
        self.ret(value)
    def run(self):
        self.uc.emu_start(0x129b0,END+4,count=20000)
        if self.uc.reg_read(UC_ARM_REG_PC)!=END:raise ValueError('Verifier did not return normally')
        return {'return':self.uc.reg_read(UC_ARM_REG_R0),'instructions':self.steps,'signature_checks':self.finals,'modeled_services':self.events}

def main():
    assert sha(IMAGE.read_bytes())=='7a0f31814c8c838b3b8f028893471e720728c5942fc2c179850d43af7115f7e2'
    original=CAP.read_bytes();assert sha(original)=='c7b12934cd0904a9cd4cfca53f656931bd5164e3bc30b99b043c2c2cb39a92d1'
    cases=[]
    for name,offset,file_failure,expected in [('original',None,False,0),('modified_main_dxe',0x1841000,False,1),('changed_certificate',0x358,False,1),('file_read_failure',None,True,1)]:
        data=bytearray(original)
        if offset is not None:data[offset]^=1
        result=Replay(data,file_failure).run();assert result['return']==expected,(name,result)
        cases.append({'name':name,'input_sha256':sha(data),'expected_return':expected,'pass':True,**result})
    # Cross-check the successful native-selected bytes against the independent
    # Python/OpenSSL result already established for this exact original CAP.
    previous=json.loads((HERE.parent/'release_review/original_static_review.json').read_text())
    assert cases[0]['signature_checks'][1]['digest']==previous['firmware_signed_digest']
    report={'target':bind(IMAGE),'capsule':bind(CAP),'script':bind(Path(__file__)),'elf_reader':bind(HERE/'elf32.py'),
            'native_function':'PDK_VerifyBiosSignature@0x129b0 (Ghidra relocated base 0x10000)',
            'engine':'Unicorn '+unicorn.__version__,'cases':cases,'crosscheck':bind(HERE.parent/'release_review/original_static_review.json'),
            'scope':'Actual original ARM control flow and byte selection; file/allocator/OpenSSL imports are explicit Python models. Crypto results are computed, never unconditional success.',
            'limits':['Not a running BMC test.','No updater state-machine or hardware acceptance claim.','No self-signed candidate or private key generated.','No firmware image output; negative controls exist only in memory.'],
            'hardware_access':False,'flashable':False}
    (HERE/'bmc_verifier_replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'cases':[{k:r[k] for k in ['name','return','pass']} for r in cases],'report':str(HERE/'bmc_verifier_replay.json')}))

if __name__=='__main__': main()
