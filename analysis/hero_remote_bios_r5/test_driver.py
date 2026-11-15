from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_driver.c'),'-o',str(out/'test_driver.obj')]
# Reuse the release freestanding target and warning policy, no host C runtime.
subprocess.run(cmd,check=True)
link=Path(compile[0]).with_name('zig.exe')
dll=out/'test_driver.dll'
subprocess.run([str(link),'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_driver.obj'),str(out/'settings.obj'),str(out/'crc.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['no write before app exit','two consecutive native-unlocked samples','exact one-byte update','validated journal before write','single attempt, including denied writes','restore and journal deletion','refuse changed full Setup or malformed journal','cancel, reentry cancel, 300-second timeout','wrong target, attributes, size, state, value and stale CRC','readback corruption and journal cleanup failure']}
(out/'driver-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
