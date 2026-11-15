"""Bind the agreed immutable production payload manifest to the EFI build.
This freezes local review inputs; it does not authorize hardware deployment.
"""
import json
from build_loader import OUT,sha

def main():
    parent=OUT.parent;manifest=parent/'payload_manifest.json'
    expected='d95d73120917924f230c7c819132cb13d7ffb4ca52f2f5c958c00fd25e01746e'
    assert sha(manifest)==expected
    payload=json.loads(manifest.read_text());assert payload['status']=='FROZEN_PAYLOAD_ONLY'
    records={f['path']:f for f in payload['files']}
    for key in ['build/production/CAPACITY01.IMG','build/production/init','build/commandline.txt']:
        rec=records[key];p=parent/key;assert p.stat().st_size==rec['bytes'] and sha(p)==rec['sha256']
    kernel=parent/'official/vmlinuz-lts';initrd=parent/'build/production/CAPACITY01.IMG'
    assert kernel.stat().st_size==13706240 and sha(kernel)=='9d6eff6e7bcd5f5fba623f7a44c565ca6914da2b91110a8dc72a3a63cb088693'
    assert initrd.stat().st_size==1013927 and sha(initrd)=='3f1e21419c1b0dd82ac0a23d526bfa647084c9f1edcad2f649051283b1ec6989'
    cmdline=(parent/'build/commandline.txt').read_text(encoding='ascii');assert '\n' not in cmdline and len(cmdline)==197
    contract={'status':'FROZEN_LOCAL_REVIEW','scope':'Pinned production payload for local review and simulation; no hardware authorization','payload_manifest_sha256':expected,'cmdline':cmdline,'kernel':{'path':str(kernel),'bytes':kernel.stat().st_size,'sha256':sha(kernel)},'initrd':{'path':str(initrd),'bytes':initrd.stat().st_size,'sha256':sha(initrd)}}
    dest=OUT/'candidate/contract.json';dest.parent.mkdir(parents=True,exist_ok=True);data=json.dumps(contract,indent=2).encode('utf8')
    if dest.exists():assert dest.read_bytes()==data,'Refusing to replace a different existing frozen contract'
    else:dest.write_bytes(data)
    print(json.dumps({'contract':str(dest),'sha256':sha(dest)},indent=2))
if __name__=='__main__':main()
