from build_test_common import *
OUT=HERE/'ram_test'
SRC,copied,commands,binding=snapshot(OUT)
driver=SRC/'production/driver';p3=SRC/'p3'
source=(driver/'entry.c').read_text(encoding='utf8')
guids='\n'.join(line for line in source.splitlines() if line.startswith(tuple('static GUID '+name for name in ['loaded_guid','browser_guid','smbios3_guid','smbios_guid','tse_guid','setup_guid'])))
functions=source[source.index('static int equal_ascii('):source.index('static void EA discover(')]
(SRC/'target_detect.h').write_text(guids+'\n'+functions,encoding='utf8')
copy(HERE/'ram_lock_test.c',SRC/'ram_lock_test.c')
(SRC/'kvm.c').write_text((p3/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG','AI TWEAKER SAGE P5 - RAM TEST'),encoding='utf8')
objects=[]
for file in [SRC/'ram_lock_test.c',SRC/'kvm.c',p3/'vendor/qrcodegen.c']:
    obj=OUT/(file.stem+'.obj');objects.append(obj);compile(file,obj,[driver,SRC,p3,p3/'compat'],commands)
linked=[name for name in OBJECTS if name!='entry']
objects += [copied/(name+'.obj') for name in linked]
efi=OUT/'BOOTX64.EFI';link(objects,efi,OUT/'ram_test.map',commands)
target=iso(efi,OUT,'AiTweaker-SAGE-P5-RAM-Test.iso','AITWK_SAGE_P5')
finish(OUT,SRC,efi,target,binding|{'scope':'SAGE maintenance-only RAM credential and resident hook test. No flash or filesystem write code. Runtime SetVariable table calls and saved chain are blocked; OEM direct/cached/SMM writes are not proven absent. Reset required once services initialize.','linked_objects':{name:sha(copied/(name+'.obj')) for name in linked},'send_form_rva':'0x20ee4'},commands,Path(__file__))
