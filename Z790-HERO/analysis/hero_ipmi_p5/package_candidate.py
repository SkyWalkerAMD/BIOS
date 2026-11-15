"""Package a clearly labelled test candidate, original recovery and evidence."""
from pathlib import Path
import json,hashlib,zipfile
P=Path(__file__).resolve().parent;ROOT=P.parents[1]
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    verified=json.loads((P/'candidate-verification.json').read_text());assert verified['passed']
    preflight=ROOT/'analysis/hero_ipmi_p5_live_20261103'
    live=json.loads((preflight/'preflight-result.json').read_text());assert live['probe_returned_success'] and live['pci_memory_bit_restored']
    files={}
    def add(name,path):files[name]=Path(path).read_bytes()
    add('01-TEST-CANDIDATE/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP',P/'candidate/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP')
    assert sha(files['01-TEST-CANDIDATE/HERO-3107-IPMI-P5-RC1-UNSIGNED.CAP'])==verified['candidate_sha256']
    official=ROOT/'analysis/hero_3107_official'
    add('02-OFFICIAL-RECOVERY/MZ790H.CAP',official/'ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP')
    assert sha(files['02-OFFICIAL-RECOVERY/MZ790H.CAP'])=='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
    add('02-OFFICIAL-RECOVERY/source.json',official/'source.json')
    add('03-DIAGNOSTIC/HERO-IPMI-P5-PREFLIGHT.iso',P/'HERO-IPMI-P5-PREFLIGHT.iso')
    for f in (P/'USB').rglob('*'):
        if f.is_file():add('03-DIAGNOSTIC/USB/'+f.relative_to(P/'USB').as_posix(),f)
    for f in (P/'source').rglob('*'):
        if f.is_file():add('04-SOURCE/source/'+f.relative_to(P/'source').as_posix(),f)
    for f in P.glob('*.py'):add('04-SOURCE/'+f.name,f)
    add('04-SOURCE/workspace-dependencies/hero_ipmi_p3/generate_forms.py',ROOT/'analysis/hero_ipmi_p3/generate_forms.py')
    add('04-SOURCE/workspace-dependencies/uefi_vm_20261015/disk_images.py',ROOT/'analysis/aitweaker_lock/uefi_vm_20261015/disk_images.py')
    for f in (P/'host-lzma').iterdir():
        if f.suffix in ('.c','.h','.json'):add('04-SOURCE/host-lzma/'+f.name,f)
    for name in ('native-payload.json','native-verification.json','build.json','publisher-tests.json','policy-tests.json','candidate-build.json','candidate-verification.json','original-parser-output.txt','candidate-parser-output.txt'):
        add('05-EVIDENCE/'+name,P/name)
    for name in ('preflight-result.json','P5-preflight.txt'):add('05-EVIDENCE/'+name,preflight/name)
    for name in live['screens']:add('05-EVIDENCE/screens/'+name,preflight/'screens'/name)
    review=ROOT/'analysis/hero_ipmi_p5_review_live_20261103'
    if (review/'image-check-result.json').exists():
        check=json.loads((review/'image-check-result.json').read_text());add('05-EVIDENCE/image-check-result.json',review/'image-check-result.json')
        for name in check.get('screens',[]):add('05-EVIDENCE/image-check/'+name,review/'screens'/name)
    for name in ('使用说明-P5-RC1.txt','构建与实测记录-P5.txt'):add(name,P/name)
    manifest={name:dict(bytes=len(b),sha256=sha(b)) for name,b in sorted(files.items())}
    files['SHA256-MANIFEST.json']=(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
    # Reject accidental secrets in every textual deliverable. Credential values
    # are deliberately not embedded even in this check or the source bundle.
    for name,b in files.items():
        if name.endswith(('.txt','.json','.py','.c','.h')):
            for line in b.splitlines():
                assert not line.strip().lower().startswith((b'authorization: basic ',b'x-auth-token:')),name
    dest=ROOT/'analysis/HERO-3107-IPMI-P5-RC1-TEST-AND-RECOVERY.zip'
    with zipfile.ZipFile(dest,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,b in files.items():z.writestr(name,b)
    with zipfile.ZipFile(dest) as z:
        assert z.testzip() is None
        for name,b in files.items():assert z.read(name)==b
    report=dict(package=str(dest),bytes=dest.stat().st_size,sha256=sha(dest.read_bytes()),files=len(files),native_hardware_passed=False,official_release=False,driver_preflight_passed=True)
    (P/'delivery.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
