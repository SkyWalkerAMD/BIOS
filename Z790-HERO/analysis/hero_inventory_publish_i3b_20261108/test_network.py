from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_network.c'),'-o',str(out/'test_network.obj')]
subprocess.run(cmd,check=True)
dll=out/'test_network.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_network.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['unique USB target selection','wrong board and missing/ambiguous/non-USB NIC refusal','bounded malformed device-path rejection','exact GET service-root URL and no body','configure failure cleanup','request/response timeout cancellation','failed destroy retains callback resources and blocks reuse until cleanup']}
(out/'network-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
