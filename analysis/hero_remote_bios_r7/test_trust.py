from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_trust.c'),'-o',str(out/'test_trust.obj')]
subprocess.run(cmd,check=True)
dll=out/'test_trust.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_trust.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['wrong platform refused','existing trust store never overwritten','BS-only create and exact readback','create/delete/readback failures','cleanup retains ownership on failure','changed value not deleted','cleanup retry and absence verified']}
(out/'trust-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
