"""Independent current BMC PDK replay of the separately made NON-OEM CAP.
Only reads the pinned public candidate; does not load or create private keys.
"""
from pathlib import Path
import hashlib,json
from replay_bmc1313_signatures import CryptoVM, HERE, ROOT, PDK

def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 candidate=HERE.parent/'engineering_signature/W790-ACE-1904-CANDIDATE05-ENGINEERING-NONOEM-NOT-FLASH-READY.CAP'
 baseline=HERE.parent/'lock_1904_candidate05/lab/asus_review/W790-ACE-1904-lock.review.bin'
 data=candidate.read_bytes();original=baseline.read_bytes()
 assert sha(data)=='e330039ecd2c334c4f9d502589e7f9503000b34462a7e21f6b97b1b581794d08'
 assert sha(original)=='9b038c4eae111a985c5c5fef460f0874338d16764b0ead6f89a3e55c775f5455'
 assert len(data)==len(original)==67112960
 allowed=[(0x48,0x148),(0x148,0x248),(0x258,0x358),(0x358,0x458)]
 assert data[4096:]==original[4096:]
 changes=[i for i,(a,b) in enumerate(zip(data[:4096],original[:4096])) if a!=b]
 assert changes and all(any(a<=i<b for a,b in allowed) for i in changes)
 assert all(data[a:b]!=original[a:b] for a,b in allowed)
 v=CryptoVM();v.files={'/var/biossig.bin':data}
 result=v.run('pdk','PDK_VerifyBiosSignature',limit=1000000)
 assert result==0 and len(v.crypto)==2 and all(x['verification']['valid'] for x in v.crypto)
 assert v.native_import_links==['read_file_append']
 assert '/var/biossig.bin' not in v.files
 report={
  'status':'PASS_ENGINEERING_CAP_CURRENT_1313_NATIVE_PDK_ONLY_NOT_FLASH_READY',
  'input':{'path':candidate.relative_to(ROOT).as_posix(),'bytes':len(data),'sha256':sha(data)},
  'baseline':{'path':baseline.relative_to(ROOT).as_posix(),'sha256':sha(original)},
  'source':{'path':PDK.relative_to(ROOT).as_posix(),'sha256':sha(PDK.read_bytes())},
  'payload_sha256':sha(data[4096:]),'payload_byte_identical_to_baseline':True,
  'only_changed_fields':[{'start':hex(a),'end_exclusive':hex(b)} for a,b in allowed],
  'changed_header_byte_count':len(changes),'header_flags_map_guid_unchanged':True,
  'native_return':result,'native_instructions':v.instructions,'native_import_links':v.native_import_links,
  'crypto':v.crypto,'messages':v.messages,'import_calls':v.calls,
  'original_and_stale_signature_controls':{'path':(HERE/'bmc1313_native_signature_replay.json').relative_to(ROOT).as_posix(),'sha256':sha((HERE/'bmc1313_native_signature_replay.json').read_bytes()),'rerun':False},
  'scope':'Actual current official PDK and read_file_append ARM instructions with closed RAM file model; crypto imports independently perform RSA/PSS public verification. Neither the BMC nor OpenSSL ARM binary is executed.',
  'limits':['Only the CAP two-stage signature predicate is covered. No resident-root tail signature, live backend identity, update acceptance, SPI write, cold boot, persistence, backup or no-POST recovery is proven.',
            'This candidate is explicitly an engineering NON-OEM artifact. Passing self-contained CAP verification does not make its key an ASUS/OEM trusted key.'],
  'private_keys_read_created_or_written':False,'BMC_access':False,'candidate_modified':False}
 output=HERE/'bmc1313_engineering_signature_replay.json'
 output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
 print(json.dumps({'status':report['status'],'return':result,'instructions':v.instructions,'output_sha256':sha(output.read_bytes())}))
if __name__=='__main__':main()
