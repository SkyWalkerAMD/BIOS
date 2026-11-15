"""Isolated HISTORY01 RAM-only test media; baseline production/media stay unchanged."""
import argparse
from build_test_common import *
OUT=HERE/'ram_test_history01'
CANDIDATE=HERE.parent/'navigation/history_candidate'
p=argparse.ArgumentParser();p.add_argument('--candidate-sha',required=True);p.add_argument('--platform-sha',required=True);args=p.parse_args()
def read(p):return json.loads(p.read_text(encoding='utf8'))
candidate_build=read(CANDIDATE/'build/build.json')
history=read(CANDIDATE/'history_candidate_result.json')
assert candidate_build['candidate_driver_sha256']==sha(CANDIDATE/'build/AiTweakerLock1904.efi')==args.candidate_sha
assert candidate_build['candidate_platform_sha256']==sha(CANDIDATE/'platform.c')==args.platform_sha
assert candidate_build['original_driver_sha256']==PIN
assert history['status']=='PASS_CANDIDATE_ONLY' and history['candidate_driver_sha256']==args.candidate_sha
if (OUT/'build.json').exists():assert read(OUT/'build.json')['candidate_driver_sha256']==args.candidate_sha,'History01 name already binds a different candidate'
baseline_media={name:sha(HERE/'ram_test'/name) for name in ['BOOTX64.EFI','AiTweaker-SAGE-P5-RAM-Test.iso','build.json','source-snapshot.zip']}
SRC,copied,commands,binding=snapshot(OUT)
driver=SRC/'production/driver';p3=SRC/'p3'
candidate_objects=OUT/'candidate_objects';candidate_objects.mkdir(exist_ok=True)
copy(CANDIDATE/'build/platform.obj',candidate_objects/'platform.obj')
for rel,digest in candidate_build['object_sha256'].items():assert sha(HERE.parent/rel)==digest
assert sha(candidate_objects/'platform.obj')==sha(CANDIDATE/'build/platform.obj')
for name in ['platform.c','platform.patch','build_candidate.py','verify_history.py','history_candidate_result.json']:copy(CANDIDATE/name,SRC/'history_candidate'/name)
copy(CANDIDATE/'build/build.json',OUT/'candidate-build.json')
all_objects=[(candidate_objects if name=='platform' else copied)/(name+'.obj') for name in OBJECTS]
relinked=OUT/'candidate-relinked.efi';link(all_objects,relinked,OUT/'candidate-relinked.map',commands,'efi_boot_service_driver')
assert sha(relinked)==args.candidate_sha,'Single-object overlay must reproduce exact tested candidate'
source=(driver/'entry.c').read_text(encoding='utf8')
guids='\n'.join(line for line in source.splitlines() if line.startswith(tuple('static GUID '+name for name in ['loaded_guid','browser_guid','smbios3_guid','smbios_guid','tse_guid','setup_guid'])))
functions=source[source.index('static int equal_ascii('):source.index('static void EA discover(')]
(SRC/'target_detect.h').write_text(guids+'\n'+functions,encoding='utf8')
original=(HERE/'ram_lock_test.c').read_text(encoding='utf8')
assert sha(HERE/'ram_lock_test.c')=='0c56493fabe8a384683b3e70fe0b80aefdb955768a71ca25338d08cf46ba0fd2'
label='P5_RAM_LOCK_TEST\\r\\n'
assert original.count(label)==1
source=original.replace(label,label+'Build=HISTORY01\\r\\nCandidateDriverSHA256='+args.candidate_sha+'\\r\\n').replace('Ai Tweaker SAGE P5 - TEMPORARY RAM TEST','Ai Tweaker SAGE P5 HISTORY01 - TEMPORARY RAM TEST')
(SRC/'ram_lock_test.c').write_text(source,encoding='utf8')
(SRC/'kvm.c').write_text((p3/'kvm.c').read_text(encoding='utf8').replace('AI TWEAKER P3 - KVM LOG','AI TWEAKER SAGE P5 HIST01'),encoding='utf8')
objects=[]
for file in [SRC/'ram_lock_test.c',SRC/'kvm.c',p3/'vendor/qrcodegen.c']:
    obj=OUT/(file.stem+'.obj');objects.append(obj);compile(file,obj,[driver,SRC,p3,p3/'compat'],commands)
linked=[name for name in OBJECTS if name!='entry']
linked_paths={name:(candidate_objects if name=='platform' else copied)/(name+'.obj') for name in linked}
objects += list(linked_paths.values())
efi=OUT/'BOOTX64.EFI';link(objects,efi,OUT/'ram_test.map',commands)
target=iso(efi,OUT,'AiTweaker-SAGE-P5-History01-RAM-Test.iso','AITWK_HIST01')
for name,digest in baseline_media.items():assert sha(HERE/'ram_test'/name)==digest
assert sha(DRIVER/'build/AiTweakerLock1904.efi')==PIN
result=binding|{'candidate_driver_sha256':args.candidate_sha,'candidate_platform_sha256':args.platform_sha,'candidate_platform_object_sha256':sha(candidate_objects/'platform.obj'),'candidate_relinked_sha256':sha(relinked),'candidate_build_sha256':sha(CANDIDATE/'build/build.json'),'history_test_sha256':sha(CANDIDATE/'history_candidate_result.json'),'history_test_checks':history['checks'],'linked_objects':{name:sha(path) for name,path in linked_paths.items()},'only_production_object_changed':'platform','baseline_ram_media_hashes_unchanged':baseline_media,'test_harness_changes':'Only HISTORY01 visible build identifier and candidate SHA audit text; RAM storage, write denial, snapshot and shutdown logic unchanged.','scope':'Isolated no-flash RAM credential test for history redirect candidate; no persistent deployment, no full ASUS visual simulation.'}
finish(OUT,SRC,efi,target,result,commands,Path(__file__))
