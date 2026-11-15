"""Independent UEFIExtract output + unchanged-byte audit of the full capsule."""
from pathlib import Path
from collections import defaultdict,Counter
import hashlib,json,re,subprocess
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
orig=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
new=P/'candidate/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP'
def sha(b):return hashlib.sha256(b).hexdigest()
def inventory(cap):
    found=defaultdict(list)
    for info in cap.with_suffix(cap.suffix+'.dump').rglob('info.txt'):
        s=info.read_text();m=re.search(r'^File GUID: (.+)$',s,re.M)
        if s.startswith('Type: File\n') and m:
            d=info.parent;body=d/'body.bin'
            header=(d/'header.bin').read_bytes()
            if not body.exists():assert int(re.search(r'Full size: ([0-9A-F]+)h',s)[1],16)==len(header)
            raw=header+(body.read_bytes() if body.exists() else b'')
            found[m[1].lower()].append(dict(path=d,data=raw))
    return found
def main():
    a,b=inventory(orig),inventory(new);allowed={'899407d7-99fe-43d8-9a21-79ec328cac21','fe612b72-203c-47b1-8560-a66d946eb371','9e21fd93-9c72-4c15-8c4b-e77f1db2d792'}
    added='261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
    assert set(b)-set(a)=={added} and not set(a)-set(b)
    identical=0;changed=[]
    for guid,old in a.items():
        now=b[guid];assert len(old)==len(now)
        same=Counter(sha(x['data']) for x in old)==Counter(sha(x['data']) for x in now)
        if same:identical+=len(old)
        else:assert guid in allowed;changed.append(guid)
    assert set(changed)==allowed and len(b[added])==1
    checks=[('899407d7-99fe-43d8-9a21-79ec328cac21','PE32 image section',P/'Setup-P5-RESOURCE-REVIEW.efi'),(added,'PE32 image section',P/'USB/EFI/HERO/HeroIpmiP5.efi')]
    for guid,kind,expected in checks:
        paths=[p for p in b[guid][0]['path'].rglob('body.bin') if p.parent.name.endswith(kind)]
        assert len(paths)==1 and paths[0].read_bytes()==expected.read_bytes()
    spf=b['fe612b72-203c-47b1-8560-a66d946eb371'][0]['path']
    assert any(p.read_bytes()==(P/'AMITSESetupData-P5.bin').read_bytes() for p in spf.rglob('body.bin'))
    original=orig.read_bytes();candidate=new.read_bytes();assert len(original)==len(candidate)==33558528
    assert original[:0x12d1000]==candidate[:0x12d1000] and original[0x1cc1000:]==candidate[0x1cc1000:]
    extractor=ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe';messages=[]
    for label,path in [('original',orig),('candidate',new)]:
        result=subprocess.run([str(extractor),str(path),'report'],capture_output=True,text=True,check=True)
        (P/(label+'-parser-output.txt')).write_text(result.stdout+result.stderr)
        messages.append([line for line in (result.stdout+result.stderr).splitlines() if 'Parser::' in line])
    assert Counter(messages[0])==Counter(messages[1]),'New parser warning'
    report=dict(passed=True,independent_parser='UEFIExtract NE A75',original_files=sum(map(len,a.values())),candidate_files=sum(map(len,b.values())),byte_identical_existing_files=identical,changed_ffs=changed,added_ffs=added,extracted_setup_matches=True,extracted_spf_matches=True,extracted_runtime_matches=True,outside_dxe_volume_unchanged=True,new_parser_warnings=[],inherited_parser_warnings=messages[0],candidate_sha256=sha(candidate),hardware_rendering_verified=False,signature_acceptance_verified=False)
    (P/'candidate-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='inherited_parser_warnings'},indent=2))
if __name__=='__main__':main()
