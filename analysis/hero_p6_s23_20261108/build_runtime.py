"""Build P6 resident firmware from reviewed native resource and portable backend."""
from pathlib import Path
import hashlib,json,os,struct,subprocess,sys,uuid
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools/pydeps'))
import pefile
ZIG=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def section(k,b):return (len(b)+4).to_bytes(3,'little')+bytes([k])+b
def ffs(body,g):
 h=bytearray(uuid.UUID(g).bytes_le+b'\0\xaa\x07\0'+(len(body)+24).to_bytes(3,'little')+b'\xf8')
 h[16]=(-sum(h[:16]+b'\0\0'+h[18:23]+b'\0'))&255
 return h+body
def section_stream(items):
 # OpenSectionStream rejects padding after the final section.
 body=b''
 for kind,data in items:
  body+=bytes(-len(body)%4)
  body+=section(kind,data)
 return body
def main():
 meta=json.loads((OUT/'native/native-payload.json').read_text())
 forms=(OUT/'native/Setup-forms-P6.bin').read_bytes();ids=list(meta['value_ids'].values())
 assert len(ids)==41 and sha(OUT/'native/Setup-forms-P6.bin')==meta['files']['Setup-forms-P6.bin']['sha256']
 h='/* Generated: exact P6 IFR and strings. */\nstatic const uint8_t p5_expected_forms[]={\n'
 h+=',\n'.join(','.join(map(str,forms[i:i+32])) for i in range(0,len(forms),32))+'\n};\n'
 h+='static const uint16_t p5_value_ids[V_COUNT]={'+','.join(map(str,ids))+'};\n'
 prior=json.loads((ROOT/'analysis/hero_ipmi_p5/native-payload.json').read_text())
 assert sha(ROOT/'analysis/hero_ipmi_p5/native-payload.json')==meta['source_p5_meta_sha256']
 langs=[i['language'] for i in prior['languages']]
 h+='#define P5_LANG_COUNT '+str(len(langs))+'\nstatic const char *const p5_languages[]={'+','.join(json.dumps(s) for s in langs)+'};\n'
 (OUT/'source/expected.h').write_text(h,encoding='ascii')
 old_forms=(OUT/'native/Setup-forms-P5.bin').read_bytes()
 assert len(old_forms)==326465 and hashlib.sha256(old_forms).hexdigest()=='b295f8ce9b5f38f366f3cf8c9c8895f218bd009c2a9c9144ea2ff6c5ff3f98c8'
 assert len(forms)==327223 and hashlib.sha256(forms).hexdigest()=='3ec34187a90cfefeac1728a8e7b67e447d6bafc07d5d30d61d4396c94c0fef08'
 old_ids=list(prior['value_ids'].values());assert len(old_ids)==40 and ids[:40]==old_ids
 h='/* Generated: complete known P5 readonly Forms. Never an approximate match. */\n'
 h+='#define P5_READONLY_VALUE_COUNT 40U\n'
 h+='static const uint8_t p5_readonly_forms[]={\n'+',\n'.join(','.join(map(str,old_forms[i:i+32])) for i in range(0,len(old_forms),32))+'\n};\n'
 h+='#define P5_READONLY_FORM_SHA256 "B295F8CE9B5F38F366F3CF8C9C8895F218BD009C2A9C9144EA2FF6C5FF3F98C8"\n'
 h+='#define P6_FORM_SHA256 "3EC34187A90CFEFEAC1728A8E7B67E447D6BAFC07D5D30D61D4396C94C0FEF08"\n'
 (OUT/'source/expected_p5.h').write_text(h,encoding='ascii')
 env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(OUT/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(OUT/'zig-local')
 flags=['-target','x86_64-unknown-windows-msvc','-nostdinc','-isystem',str(ZIG.parent/'lib/include'),'-I',str(OUT/'source/compat'),'-I',str(OUT/'backend'),'-DNDEBUG','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone','-fshort-wchar','-ffunction-sections','-fdata-sections']
 commands=[];names=['common','probe_core','command_policy','presentation','publisher','transport','settings','driver','p6_backend']
 for name in names:
  src=OUT/('backend' if name=='p6_backend' else 'source')/(name+'.c')
  cmd=[str(ZIG),'clang',*flags,'-c',str(src),'-o',str(OUT/(name+'.obj'))]
  subprocess.run(cmd,env=env,check=True,cwd=ROOT);commands.append(cmd)
 output=OUT/'HeroIpmiP6.efi'
 cmd=[str(ZIG),'lld-link','/subsystem:efi_boot_service_driver','/entry:efi_main','/nodefaultlib','/machine:x64','/dynamicbase','/fixed:no','/nxcompat','/opt:ref','/opt:noicf','/timestamp:0','/map:'+str(OUT/'driver.map'),'/out:'+str(output)]+[str(OUT/(n+'.obj')) for n in names]
 subprocess.run(cmd,env=env,check=True,cwd=ROOT);commands.append(cmd)
 pe=pefile.PE(str(output));pe.OPTIONAL_HEADER.CheckSum=pe.generate_checksum();output.write_bytes(pe.write());pe=pefile.PE(str(output))
 assert pe.FILE_HEADER.Machine==0x8664 and pe.OPTIONAL_HEADER.Subsystem==11 and pe.verify_checksum()
 assert not hasattr(pe,'DIRECTORY_ENTRY_IMPORT') and not pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
 contents=(OUT/'driver.map').read_text()
 for s in ('config_write','lock_write','config_read','lock_read'):assert s not in contents,s
 deps=['ef9fc172-a1b2-4693-b327-6d32fc416042','0fd96974-23aa-4cdc-b9cb-98d17750322a','6441f818-6362-4e44-b570-7dba31dd2453']
 dx=b''
 for i,g in enumerate(deps):dx+=b'\x02'+uuid.UUID(g).bytes_le+(b'\x03' if i else b'')
 dx+=b'\x08'
 body=section_stream([(0x13,dx),(0x10,output.read_bytes()),(0x15,'HeroIpmiNativeP6\0'.encode('utf-16-le'))])
 fp=OUT/'HeroIpmiNativeP6.ffs';fp.write_bytes(ffs(body,'261135b0-7b73-49c0-bcc8-2f9cf4eef19e'))
 report=dict(version='P6 S23 exact P5 readonly + P6 resource compatibility; unchanged S22 transport/settings/lifecycle; no CAP',driver_bytes=output.stat().st_size,driver_sha256=sha(output),ffs_sha256=sha(fp),depex=deps,native_forms_sha256=sha(OUT/'native/Setup-forms-P6.bin'),readonly_p5_forms_sha256=sha(OUT/'native/Setup-forms-P5.bin'),commands=commands,sources={str(p.relative_to(OUT)):sha(p) for d in ['source','backend'] for p in (OUT/d).glob('*') if p.is_file() and p.suffix in ['.h','.c']})
 (OUT/'runtime-build.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('commands','sources')},indent=2))
if __name__=='__main__':main()
