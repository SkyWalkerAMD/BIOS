from pathlib import Path
import ctypes,hashlib,json,subprocess
BASE=Path(__file__).resolve().parents[1]
first=json.loads((BASE/'build.json').read_text())['commands'][0]
obj=BASE/'tests/test_loader.obj';dll=BASE/'tests/test_loader.dll'
subprocess.run(first[:-4]+['-c',str(BASE/'tests/test_loader.c'),'-o',str(obj)],check=True)
subprocess.run([first[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(obj)],check=True)
lib=ctypes.CDLL(str(dll));result=lib.run_tests();checks=lib.get_checks()
report={'passed':result==0,'failure_line':result,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'scope':'Actual C loader with strict fake UEFI and embedded real PE bytes; no native network driver executed.','coverage':['missing/ambiguous/malformed USB NII refused','only verified BMC controller and private driver binding invoked','no global ConnectController','native enabled stack reused without loading','TPL8 refused','NetworkStackVar missing/short/invalid refused before any LoadImage','every LoadImage/StartImage/DriverBinding.Start failure stops','missing per-controller service stops','second call never repeats attempt']}
(BASE/'tests/loader-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2));assert result==0
