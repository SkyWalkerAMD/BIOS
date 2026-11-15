from pathlib import Path
import hashlib,json,shutil,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;BOARD=HERE.parent
for folder in ['inputs','rea','rea_text']: (HERE/folder).mkdir(exist_ok=True)
source=BOARD/'navigation/modules/AMITSE.efi';raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='43f80bf738e0b1101431b7319a8a9c0060655e708f22f5b6379620aee862e6fe'
target=HERE/'inputs/AMITSE.efi';target.write_bytes(raw)
(HERE/'input_identity.json').write_text(json.dumps(dict(source=str(source),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),copy=str(target)),indent=2)+'\n')
steps=[('open_binary',dict(path=str(target),provider_id='ghidra'))]
steps += [('analyze_function',dict(procedure=hex(address),detail='complete')) for address in [0x1c958,0x331a4,0x3fed4,0x40094,0x3f414,0xfd6c,0x1fcb4]]
steps += [('xrefs',dict(address=hex(address))) for address in [0xbaaf8,0xafcd8,0x1c958,0x331a4,0x1fcb4,0x3fed4]]
for i,(name,arguments) in enumerate(steps,1):
 (HERE/'rea'/f'command-{i:03}.json').write_text(json.dumps(dict(name=name,arguments=arguments),indent=2)+'\n')
print(json.dumps(dict(commands=len(steps),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())))
