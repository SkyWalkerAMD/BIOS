"""Check the new fingerprint parser against generated model + real OVMF logs."""
from pathlib import Path
import hashlib,json
from decode_hii06 import analyze
HERE=Path(__file__).resolve().parent;OUT=HERE/'build';checks=[]
def accept(name,data):
 r=analyze(data);checks.append({'case':name,'passed':True});return r
def reject(name,data):
 try:analyze(data)
 except (ValueError,UnicodeError):checks.append({'case':name,'passed':True});return
 raise AssertionError(name)
def main():
 data=(OUT/'efi_cases/normal.txt').read_bytes();r=accept('model13',data);assert len(r['forms'])==13 and len(r['unknown_25fd_instances'])==2 and sum(f['baseline_match'] for f in r['forms'])==11
 for p in sorted((OUT/'efi_cases').glob('*.txt')):accept('model-'+p.stem,p.read_bytes())
 for vm in json.loads((OUT/'ovmf_tests.json').read_text())['results']:accept('realOVMF-'+vm['name'],(OUT/vm['folder']/'RESTORED-LOG.TXT').read_bytes())
 reject('truncated',data[:-1]);reject('wrong_version',data.replace(b'HII06_FINGERPRINTS',b'HII07_FINGERPRINTS',1))
 line=next(x for x in data.splitlines(keepends=True) if x.startswith(b'F6 '));reject('duplicate_instance_record',data.replace(line,line+line,1))
 match=next(x for x in data.splitlines(keepends=True) if x.startswith(b'M6 ') and b'C=MATCH' in x);bad=match[:match.index(b' N=')+3]+b'0'*64+match[match.index(b' N=')+67:];reject('forged_normalized_match',data.replace(match,bad,1))
 reject('record_count_mismatch',data.replace(b'H6.RECORDS=0000000B0000000D',b'H6.RECORDS=0000000B0000000C'))
 reject('invalid_hex',data.replace(line,line.replace(b' S=',b' S=Z',1),1))
 report={'passed':True,'count':len(checks),'checks':checks,'efi_sha256':hashlib.sha256((OUT/'BOOTX64.EFI').read_bytes()).hexdigest(),'decoder_sha256':hashlib.sha256((HERE/'decode_hii06.py').read_bytes()).hexdigest()};(OUT/'decoder_tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':True,'count':len(checks)}))
if __name__=='__main__':main()
