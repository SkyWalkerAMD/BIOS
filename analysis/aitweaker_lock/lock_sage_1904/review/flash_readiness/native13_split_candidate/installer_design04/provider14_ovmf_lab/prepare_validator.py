from pathlib import Path
import hashlib,json,shutil
HERE=Path(__file__).resolve().parent;D04=HERE.parent
OLD=D04/'ram_test05_delivery_review/final_binding_9115f1afbab01b62'
APP=D04/'ram_transaction08/ui_independent_review/inputs'
OUT=HERE/'tx08_validator_e0793175';OUT.mkdir()
shutil.copytree(APP,OUT/'inputs')
provider=D04/'provider14_chrome07/build/AiTweakerSplitProvider14.UNSIGNED.local.efi'
shutil.copyfile(provider,OUT/'inputs'/provider.name)
origins=[]
for name in ['run.py','probe.c']:
    source=OLD/name;text=source.read_text(encoding='utf8')
    for old,new in [
        ('SageNative13RamTest05.efi','SageNative13RamTest08.efi'),
        ('AiTweakerSplitProvider13.UNSIGNED.local.efi','AiTweakerSplitProvider14.UNSIGNED.local.efi'),
        ('9115f1afbab01b624ed8e3da6cdba74c52e187785c77095e1544a6211a8dc6f3','e0793175f78b6488c8222b65f0d5321d97e881bd06dca033a314d3fa8d307486'),
        ('caa80df1fa6414d635d28a3b65fec1c265968482ddb66268412483eff95deca9','495fe43ffa8ebb685c1346501a08c2d2932bc94d62809ab01b3f019d33029630'),
        ('TX05','TX08'),('P13','P14')]:text=text.replace(old,new)
    (OUT/name).write_text(text,encoding='utf8',newline='\n')
    origins.append({'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
(OUT/'origins.json').write_text(json.dumps({'old_preserved':True,'source_reference':origins,'scope':'Actual unchanged full TX08 pre-start validator; app and provider EFI entrypoints are not started in this specific fixture.'},indent=2)+'\n')
print(OUT)
