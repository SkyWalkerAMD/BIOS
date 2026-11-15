"""Determine the selected verifier's trust boundary, entirely in process RAM.

Ephemeral test keys and altered capsules are never written to disk or uploaded.
This is not an updater and does not establish hardware acceptance or safe boot.
"""
from pathlib import Path
import hashlib,json,sys
from replay_bmc_verifier import HERE,ROOT,CAP,IMAGE,Replay,bind
sys.path.insert(0,str(ROOT/'tools/hero-ipmi-readonly/site'))
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa,padding,utils
sys.path.insert(0,str(HERE.parent/'release_review'))
from verify_w890_original import capsule,firmware_digest

def main():
    original=CAP.read_bytes();data=bytearray(original)
    root=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    root_n=root.public_key().public_numbers().n.to_bytes(256,'big')
    leaf_n=leaf.public_key().public_numbers().n.to_bytes(256,'big')
    data[0x258:0x358]=root_n;data[0x48:0x148]=leaf_n;data[0x1841000]^=1
    broken=Replay(data).run();assert broken['return']==1
    pss=padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=8)
    data[0x358:0x458]=root.sign(leaf_n,pss,hashes.SHA256())
    digest=firmware_digest(data,capsule(data))
    data[0x148:0x248]=leaf.sign(digest,pss,utils.Prehashed(hashes.SHA256()))
    matched=Replay(data).run();assert matched['return']==0
    data[0x1841001]^=1
    stale=Replay(data).run();assert stale['return']==1
    report={'target':bind(IMAGE),'original_capsule':bind(CAP),'script':bind(Path(__file__)),
        'replay_implementation':bind(HERE/'replay_bmc_verifier.py'),
        'cases':[{'name':'new_public_keys_with_original_signatures','pass':True,**broken},
                 {'name':'changed_DXE_with_ephemeral_matching_chain','pass':True,**matched},
                 {'name':'further_change_after_ephemeral_signing','pass':True,**stale}],
        'observation':'This exact PDK verifier accepts an internally consistent capsule-contained test key chain. It does not establish an OEM trust anchor by itself.',
        'correction':'Original signature invalidation alone does NOT prove all BMC update routes require the unavailable OEM private key.',
        'limits':['This is one original ARM function with explicit I/O/OpenSSL models, not the complete BMC updater.',
                  'Public package backend identity on installed hardware is not directly measured; only its full frontend matches the earlier live capture.',
                  'No claim of safe flash, board-specific metadata preservation, Boot Guard acceptance or no-POST recovery.',
                  'No altered firmware artifact, private key or public-key replacement material was persisted or uploaded.'],
        'altered_capsules_written':False,'keys_persisted':False,'device_access':False,'release_ready':False}
    (HERE/'bmc_trust_probe.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'cases':[(x['name'],x['return']) for x in report['cases']],'release_ready':False}))

if __name__=='__main__': main()
