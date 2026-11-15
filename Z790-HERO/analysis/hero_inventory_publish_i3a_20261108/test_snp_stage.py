from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
compile=json.loads((out/'build.json').read_text())['commands'][0]
subprocess.run(compile[:-4]+['-c',str(out/'test_snp_stage.c'),'-o',str(out/'test_snp_stage.obj')],check=True)
dll=out/'test_snp_stage.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_snp_stage.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['NII path, protocol version/type and unique-controller target matching','unchanged NetworkStackVar bounded read and read failure refusal','existing SNP and passive per-boot marker duplicate refusal','exact image length/CRC before loading','binding image handle identity','direct single binding only, no ConnectController recursion or IP stack','load/start/support/bind failures stop progression','no SetVariable, BMC/IPMI or network packet API in mock table']}
(out/'snp-stage-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));assert failure==0
