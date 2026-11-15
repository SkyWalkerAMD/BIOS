from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_tls_client.c'),'-o',str(out/'test_tls_client.obj')]
subprocess.run(cmd,check=True)
dll=out/'test_tls_client.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_tls_client.obj'),str(out/'gzip.obj'),str(out/'crc.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['verified USB interface and exact IPv4 TCP443','TLS1.2 VERIFY_PEER and exact hostname','public CA native TLS configuration','short TCP reads and record bounds','no HTTP data before verified handshake','protocol setup failures','rejected certificate','bounded timeout','resource ownership on failed cleanup','retry and reuse gates','fragment allocation balance','strict HTTP Content-Length framing and error status distinction','all truncated response prefixes and duplicate length refusal','fixed resource/method table with bounded publication bodies; arbitrary URL and SD unavailable','exact leaf pin success and mismatch refusal before HTTP','TLS cryptographic handshake still required after pin match','every certificate message split boundary','missing/duplicate/malformed certificate and early ChangeCipherSpec refusal','actual gzip registry HTTP response decoded and corrupted gzip CRC refused at TLS-client integration boundary']}
(out/'tls-client-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
