from pathlib import Path
import ctypes,json,hashlib,subprocess
out=Path(__file__).resolve().parent
manifest=json.loads((out/'build.json').read_text())
compile=manifest['commands'][0]
cmd=compile[:-4]+['-c',str(out/'test_tls_client.c'),'-o',str(out/'test_tls_client.obj')]
subprocess.run(cmd,check=True)
dll=out/'test_tls_client.dll'
subprocess.run([compile[0],'lld-link','/dll','/noentry','/nodefaultlib','/machine:x64','/opt:ref','/export:run_tests','/export:get_checks','/out:'+str(dll),str(out/'test_tls_client.obj'),str(out/'gzip.obj'),str(out/'crc.obj'),str(out/'inventory_legacy71.obj')],check=True)
d=ctypes.CDLL(str(dll));failure=d.run_tests();checks=d.get_checks()
result={'passed':failure==0,'failure_line':failure,'assertions':checks,'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'coverage':['13 fixed GET paths; only Memory POST and System PATCH, CPU POST rejected','actual native exact-body guard accepts only four DIMMs and 71-byte summary','exact .71 leaf pin match and mismatch before HTTP','TLS1.2 cryptographic handshake and negotiated cipher policy','all certificate message split boundaries','non-pinned exchange refused before allocation','capability URL and four exact donor headers','short TCP reads and strict HTTP/gzip framing','HTTP error status retained','failed cleanup retains callbacks and blocks reuse','bounded log capacity refusal before new request','invalid resource IDs and null replies refused','all method/resource allowlist combinations','exact If-Match and Content-Length with injection refusal','exact-source/watchdog failure refuses writes before TLS allocation','960000 bytes reserved for post-write readback','write never sent when pin or cryptographic handshake fails']}
(out/'tls-client-tests.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));assert failure==0
