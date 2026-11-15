from build_test_common import *
OUT=HERE/'preflight'
SRC,copied,commands,binding=snapshot(OUT)
driver=SRC/'production/driver';p3=SRC/'p3'
services=(driver/'services.c').read_text(encoding='utf8');entry=(driver/'entry.c').read_text(encoding='utf8')
walk=services[services.index('int memory_present('):services.index('int patch_memory(')]
board=entry[entry.index('static int equal_ascii('):entry.index('static int image_guid(')]
guids='\n'.join(line for line in entry.splitlines() if line.startswith(('static GUID smbios3_guid','static GUID smbios_guid')))
copy(HERE/'preflight_extra.c',SRC/'preflight_extra.c')
extra=walk+'\n'+guids+'\n#define system_table st\n#define memcmp(a,b,n) (!equal((a),(b),(n)))\n'+board+'\n#undef memcmp\n#undef system_table\n'+(SRC/'preflight_extra.c').read_text(encoding='utf8')
probe=(p3/'probe.c').read_text(encoding='utf8')
assert probe.count('/* No SimpleFileSystem or RuntimeServices are called. Display-only log export. */')==1
probe=probe.replace('/* No SimpleFileSystem or RuntimeServices are called. Display-only log export. */',extra+'\n/* P4 adds read-only RuntimeServices metadata queries. */')
probe=probe.replace('inspect_images();inspect_protocols();inspect_hii();','inspect_images();inspect_protocols();inspect_hii();inspect_preflight();')
probe=probe.replace('Ai Tweaker P3 KVM - collecting read-only inventory...','Ai Tweaker SAGE P4 - read-only lock preflight...')
(p3/'probe.c').write_text(probe,encoding='utf8')
(p3/'kvm.c').write_text((p3/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG','AI TWEAKER SAGE P4 - PREFLIGHT'),encoding='utf8')
profiles=(p3/'profiles.h').read_text(encoding='utf8');new=[]
for module,guid,crc in [('AMITSE','{0xb1da0adf,0x4f77,0x4070,{0xa8,0x8e,0xbf,0xfe,0x1c,0x60,0x52,0x9a}}',0x8a65ad70),('Setup','{0x899407d7,0x99fe,0x43d8,{0x9a,0x21,0x79,0xec,0x32,0x8c,0xac,0x21}}',0xe94c541a)]:
    p=pefile.PE(str(HERE.parent/f'analysis/modules/{module}.efi'));t=next(s for s in p.sections if s.Name.rstrip(b'\0')==b'.text')
    new.append('{'+guid+f',{crc}U,{t.VirtualAddress}U,{t.Misc_VirtualSize}U,{p.OPTIONAL_HEADER.AddressOfEntryPoint}U,{p.OPTIONAL_HEADER.SizeOfImage}U,"W790E_SAGE_SE_1904/{module}"'+'}')
profiles=profiles.replace('\n};',',\n'+',\n'.join(new)+'\n};');(p3/'profiles.h').write_text(profiles,encoding='utf8')
objects=[]
for name in ['probe','probe_core','kvm','vendor/qrcodegen']:
    obj=OUT/(Path(name).name+'.obj');objects.append(obj);compile(p3/(name+'.c'),obj,[p3,p3/'compat'],commands)
efi=OUT/'BOOTX64.EFI';link(objects,efi,OUT/'preflight.map',commands)
target=iso(efi,OUT,'AiTweaker-SAGE-P4-Preflight.iso','AITWK_SAGE_P4')
finish(OUT,SRC,efi,target,binding|{'purpose':'Read-only SAGE SE 1904 hardware preflight; no hooks or password changes','production_memory_walk_and_board_match_reused':True},commands,Path(__file__))
