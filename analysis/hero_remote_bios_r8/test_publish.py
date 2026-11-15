from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_publish.c'),'-o',str(out/'test_publish.obj')]
subprocess.run(cmd,check=True)
dll=out/'test_publish.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_publish.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['exact HERO3107 and Setup size/attributes','two matching observations and prewrite recheck','missing BIOS and no foreign BIOS registry gates','registry read-only verification','byte-exact XML readback','HTTP error/timeout stops without retries of mutations','current values published only after catalog verified','no queue read or UEFI setting write','duplicate/escaped duplicate JSON keys and every truncated registry prefix','all transport/read stages fail closed','R8b layout update requires exact owned XML, read-only registry and live-current match; no registry/current write','layout refresh already-current no-op, each failure stage, stale Setup, foreign registry and nonconvergent upload']}
(out/'publish-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
