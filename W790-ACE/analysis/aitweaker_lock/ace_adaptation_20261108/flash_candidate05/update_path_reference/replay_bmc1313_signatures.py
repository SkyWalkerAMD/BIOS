"""Actual current-version ARM instructions, RAM files, mathematical public-key crypto.

The firmware is emulated, never loaded as native host code. Every imported file,
crypto and I/O call is a closed model. No network, device, signing, key generation,
image mutation, or update command is performed.
"""
from pathlib import Path
import ast, hashlib, importlib.util, json, struct, sys, uuid
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OLD=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/update_chain_review05'
sys.path.insert(0,str(OLD))
spec=importlib.util.spec_from_file_location('closed_vm',OLD/'replay_chain.py')
vm=importlib.util.module_from_spec(spec);spec.loader.exec_module(vm)
PDK=HERE/'bmc1313_inputs/usr/local/lib/libpdkapp.so.13.2.0'
vm.SOURCES={'pdk':PDK}
vm.PINS={'pdk':'afb0816890841a0bf6c4edaea734242a8cb04bc7c6fff11177d83decb8b1c98d'}
HELPER=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/verify_capsule_static.py'
scope={'hashlib':hashlib,'uuid':uuid,'SHA256_GUID':'51aa59de-fdf2-4ea3-bc63-875fb7842ee9'}
tree=ast.parse(HELPER.read_text(encoding='utf8'))
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in {'sha','require','guid','mgf1','rsa_pss_sha256'}],type_ignores=[]),str(HELPER),'exec'),scope)

class CryptoVM(vm.VM):
 def __init__(self):
  self.objects={};self.crypto=[];self.messages=[];self.native_import_links=[]
  super().__init__(['pdk'])
 def obj(self,value):
  p=self.alloc(32);self.objects[p]=value;return p
 def code(self,uc,pc,size,user):
  if pc in self.plt and self.plt[pc][1] in ('read_file_append','read_file'):
   label,name=self.plt[pc];self.native_import_links.append(name)
   uc.reg_write(vm.UC_ARM_REG_PC,self.addr(label,name));return
  super().code(uc,pc,size,user)
 def external(self,name,a):
  x,y,z,w=a
  if name=='access':return 0 if self.text(x) in self.files else 0xffffffff
  if name=='fseek':
   f=self.handles[x];offset=y if y<0x80000000 else y-0x100000000
   f['position']={0:0,1:f['position'],2:len(self.files[f['path']])}[z]+offset;return 0
  if name=='ftell':return self.handles[x]['position']
  if name=='rewind':self.handles[x]['position']=0;return 0
  if name=='unlink':
   path=self.text(x);self.calls[-1]['ram_only_path']=path;self.files.pop(path,None);return 0
  if name=='puts':self.messages.append(self.text(x));return 0
  if name=='RSA_new':return self.obj({})
  if name=='BN_bin2bn':return self.obj(bytes(self.uc.mem_read(x,y)))
  if name=='RSA_set0_key':
   self.objects[x]={'modulus':self.objects[y],'exponent':self.objects[z]}
   assert self.objects[z]==b'\x01\x00\x01';return 1
  if name=='EVP_PKEY_new':return self.obj({})
  if name=='EVP_PKEY_assign':assert y==6;self.objects[x]=self.objects[z];return 1
  if name=='EVP_MD_CTX_new':return self.obj({})
  if name=='EVP_PKEY_CTX_new':return self.obj({'key':self.objects[x]})
  if name=='EVP_sha256':return 0x500
  if name=='EVP_DigestVerifyInit':
   key=self.u32(self.uc.reg_read(vm.UC_ARM_REG_SP));assert z==0x500
   self.objects[x]={'key':self.objects[key],'digest':hashlib.sha256(),'updates':[]};return 1
  if name=='RSA_pkey_ctx_ctrl':assert z==0x1001 and w==6;return 1
  if name=='EVP_DigestUpdate':
   b=bytes(self.uc.mem_read(y,z));o=self.objects[x];o['digest'].update(b);o['updates'].append({'bytes':z,'sha256':hashlib.sha256(b).hexdigest()});return 1
  if name=='EVP_DigestVerifyFinal':
   assert z==256;o=self.objects[x];sig=bytes(self.uc.mem_read(y,z));block=uuid.UUID(scope['SHA256_GUID']).bytes_le+o['key']['modulus']+sig
   result=scope['rsa_pss_sha256'](block,o['digest'].digest());self.crypto.append({'verification':result,'updates':o['updates']});return int(result['valid'])
  if name=='EVP_MD_CTX_free':return 0
  return super().external(name,a)

def main():
 original=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
 candidate=HERE.parent/'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin'
 inputs=[('original',original,'03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29',0),
         ('candidate05',candidate,'9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455',1)]
 rows=[]
 for label,path,pin,expected in inputs:
  data=path.read_bytes();assert hashlib.sha256(data).hexdigest()==pin
  v=CryptoVM();v.files={'/var/biossig.bin':data}
  result=v.run('pdk','PDK_VerifyBiosSignature',limit=1000000)
  assert result==expected and len(v.crypto)==2 and v.crypto[0]['verification']['valid']
  assert v.crypto[1]['verification']['valid']==(label=='original')
  assert v.native_import_links==['read_file_append']
  rows.append({'case':label,'input_path':path.relative_to(ROOT).as_posix(),'input_sha256':pin,
   'native_return':result,'expected_return':expected,'native_import_links':v.native_import_links,
   'crypto':v.crypto,'messages':v.messages,'native_instructions':v.instructions,'import_calls':v.calls,
   'ram_signature_file_unlinked':'/var/biossig.bin' not in v.files})
 report={'status':'PASS_CURRENT_1313_NATIVE_SIGNATURE_REJECTION_BOUND_TO_CANDIDATE05',
  'source':{'path':PDK.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(PDK.read_bytes()).hexdigest()},
  'functions':{'PDK_VerifyBiosSignature':'ELF 0x32fc','read_file_append':'ELF 0x3044'},'cases':rows,
  'boundary':'Actual PDK_VerifyBiosSignature and read_file_append ARM instructions. libc file operations use a RAM dictionary. OpenSSL imports are modeled with independently cross-checked RSA-2048 PSS SHA-256 public verification and fixed observed 8-byte salt; no claim that OpenSSL itself was emulated.',
  'limits':['Not a live BMC acceptance test, not full REST/authentication/IPC emulation.',
   'No new key or signature constructed; only original public moduli/signature bytes verified.',
   'Does not establish external root-key anchoring or behavior for other signature formats.'],
  'side_effects':{'network':False,'BMC':False,'target_host_file_io':False,'target_device_io':False,'image_modified':False}}
 (HERE/'bmc1313_native_signature_replay.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
 print(json.dumps({'status':report['status'],'cases':[{'name':x['case'],'return':x['native_return'],'instructions':x['native_instructions']} for x in rows]}))
if __name__=='__main__':main()
