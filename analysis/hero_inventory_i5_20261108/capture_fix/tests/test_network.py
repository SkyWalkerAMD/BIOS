from pathlib import Path
import ctypes,hashlib,json,subprocess
BASE=Path(__file__).resolve().parents[1]
first=json.loads((BASE/'build.json').read_text())['commands'][0]
obj=BASE/'tests/test_network.obj';dll=BASE/'tests/test_network.dll'
subprocess.run(first[:-4]+['-c',str(BASE/'tests/test_network.c'),'-o',str(obj)],check=True)
subprocess.run([first[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(obj)],check=True)
lib=ctypes.CDLL(str(dll));result=lib.run_tests();checks=lib.get_checks()
report={'passed':result==0,'failure_line':result,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'scope':'Actual C USB/SNP discovery and transport with fake EFI, no hardware','coverage':['exact VID/PID/class and unique control/data pair','same physical USB path with interface0/1 required','partial/cross-device/malformed/oversized enumeration refused','raw observation allowed before SMBIOS capture; network actions still require identity','physical NII distinguished from IPv4/IPv6 child handles','HTTP timeout/cancellation and failed-cleanup retention']}
(BASE/'tests/network-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));assert result==0
