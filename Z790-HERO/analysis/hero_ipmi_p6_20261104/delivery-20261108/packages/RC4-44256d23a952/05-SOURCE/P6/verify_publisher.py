"""Reuse the reviewed publisher fault matrix against new P6 resource and C DLL."""
from pathlib import Path
import hashlib,json,os,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
zig=ROOT/'tools/zig-x86_64-windows-0.14.1/zig.exe'
env=os.environ.copy();env['ZIG_GLOBAL_CACHE_DIR']=str(HERE/'zig-global');env['ZIG_LOCAL_CACHE_DIR']=str(HERE/'zig-local')
cmd=[str(zig),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/timestamp:0','/export:p5_bind','/export:p5_publish','/export:p5_package_matches','/export:p5_release','/export:gST,DATA','/export:values,DATA','/out:'+str(HERE/'publisher_test.dll')]+[str(HERE/(p+'.obj')) for p in ('publisher','common','presentation')]
subprocess.run(cmd,check=True,env=env)
prior=ROOT/'analysis/hero_ipmi_p5/test_publisher.py';original=prior.read_text();source=original
source=source.replace("(P/'native-payload.json')","(P/'native/native-payload.json')").replace("(P/'Setup-HII-P5.bin')","(P/'native/Setup-HII-P6.bin')")
source=source.replace("langs=[x['language'] for x in meta['languages']]","langs=[x['language'] for x in json.loads((P.parent/'hero_ipmi_p5/native-payload.json').read_text())['languages']]")
source=source.replace('*40','*41').replace('range(40)','range(41)').replace('400','410')
test=HERE/'publisher_matrix.py';test.write_text(source,encoding='utf-8')
subprocess.run([sys.executable,'-X','utf8',str(test)],check=True)
(HERE/'publisher-test-provenance.json').write_text(json.dumps(dict(source=str(prior.relative_to(ROOT)),sha256=hashlib.sha256(original.encode()).hexdigest(),changes=['P6 exact resource, 41 strings x 10 languages, freshly compiled DLL']),indent=2)+'\n')
