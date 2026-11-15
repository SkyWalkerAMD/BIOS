"""Public-key verification of original ACE1904 and the candidate05 revision review image.
No signing, private keys, target execution, hardware access or image output.
"""
from pathlib import Path
import ast, base64, hashlib, json, struct, subprocess, uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OPENSSL=Path('D:/OpenSSL-Win64/bin/openssl.exe')
HELPER=ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/verify_capsule_static.py'
ORIGINAL=ROOT/'analysis/aitweaker_lock/official_W790_ACE_1904/W790_ACE_1904/Pro-WS-W790-ACE-ASUS-1904.CAP'
CANDIDATE=ROOT/'analysis/aitweaker_lock/ace_adaptation_20261108/flash_candidate05/lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin'

def sha(b):return hashlib.sha256(b).hexdigest()
def identity(p):return {'path':str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p),'bytes':p.stat().st_size,'sha256':sha(p.read_bytes())}
def tlv(tag,v):
    n=len(v);l=bytes([n]) if n<128 else bytes([128+((n.bit_length()+7)//8)])+n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([tag])+l+v
def pem(n):
    der=tlv(0x30,tlv(2,b'\0'+n)+tlv(2,b'\x01\0\x01'));b=base64.b64encode(der)
    return b'-----BEGIN RSA PUBLIC KEY-----\n'+b'\n'.join(b[i:i+64] for i in range(0,len(b),64))+b'\n-----END RSA PUBLIC KEY-----\n'

def main():
    tree=ast.parse(HELPER.read_text(encoding='utf8'));names={'sha','require','guid','mgf1','rsa_pss_sha256','parse_capsule','firmware_digest','signatures'}
    scope={'hashlib':hashlib,'struct':struct,'uuid':uuid,'CAPSULE_GUID':'4a3ca68b-7723-48fb-803d-578cc1fec44d','RSA_CERT_GUID':'a7717414-c616-4977-9420-844712a735bf','SHA256_GUID':'51aa59de-fdf2-4ea3-bc63-875fb7842ee9'}
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),str(HELPER),'exec'),scope)
    original=ORIGINAL.read_bytes();candidate=CANDIDATE.read_bytes()
    assert sha(original)=='03e4330430b2510d5e9e5c9868ca64c730844992b82c6a272b815aef3d20bf29'
    assert sha(candidate)=='9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
    oh=scope['parse_capsule'](original);ch=scope['parse_capsule'](candidate)
    signatures={name:scope['signatures'](data,h) for name,data,h in [('original',original,oh),('candidate05',candidate,ch)]}
    assert all(x['valid'] for x in signatures['original'].values())
    assert signatures['candidate05']['certificate_signature']['valid']
    assert not signatures['candidate05']['firmware_signature']['valid']
    work=HERE/'openssl_public_evidence05';work.mkdir(exist_ok=True)
    for name,off in [('firmware',0x38),('certificate',0x248)]:
        (work/f'{name}.public.pem').write_bytes(pem(original[off+16:off+272]))
        (work/f'{name}.signature.bin').write_bytes(original[off+272:off+528])
    checks=[]
    for sample in signatures:
        for kind in ['firmware','certificate']:
            digest=signatures[sample][kind+'_signature']['message_digest'];key=sample+'_'+kind
            (work/f'{key}.sha256.bin').write_bytes(bytes.fromhex(digest))
            args=[str(OPENSSL),'pkeyutl','-verify','-pubin','-inkey',str(work/f'{kind}.public.pem'),'-sigfile',str(work/f'{kind}.signature.bin'),'-in',str(work/f'{key}.sha256.bin'),'-pkeyopt','digest:sha256','-pkeyopt','rsa_padding_mode:pss','-pkeyopt','rsa_pss_saltlen:8','-pkeyopt','rsa_mgf1_md:sha256']
            p=subprocess.run(args,capture_output=True,encoding='utf8',timeout=30)
            expected=signatures[sample][kind+'_signature']['valid'];assert (p.returncode==0)==expected
            checks.append({'name':key,'signature_valid':p.returncode==0,'returncode':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip(),'argv':args})
    changed=[]
    for r in oh['regions']:
        a=r['cap_offset'];b=a+r['size']
        if original[a:b]!=candidate[a:b]:changed.append({'index':r['index'],'start':a,'end_exclusive':b,'included_in_firmware_signature':r['included_by_observed_signature_rule']})
    report={'status':'PASS_PUBLIC_KEY_CROSSCHECK_ORIGINAL_VALID_CHANGED05_RETAINED_FIRMWARE_SIGNATURE_INVALID','original':identity(ORIGINAL),'candidate05_review_only':identity(CANDIDATE),'helper':identity(HELPER),'helper_use':'Only selected pure parser/public signature functions loaded by AST; existing main not run and no helper-directory output written.','script':identity(Path(__file__).resolve()),'capsule_header':oh,'header_unchanged':original[:4096]==candidate[:4096],'changed_rom_areas':changed,'pure_python_signatures':signatures,'openssl':identity(OPENSSL),'openssl_checks':checks,'scope':'Mathematical verification under retained input public keys only. This does not establish which live updater invokes this rule or the target trust policy. New valid signatures under retained OEM moduli require the corresponding signing authority; this does not prove every possible update path requires the same key.','private_key_material_used':False,'signing_performed':False,'hardware_access':False}
    (HERE/'ace_capsule_signature_review05.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':report['status'],'changed_areas':changed,'checks':[{k:r[k] for k in ['name','signature_valid']} for r in checks]},indent=2))

if __name__=='__main__':main()
