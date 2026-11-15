"""Append the reviewed M1 DXE in verified free space of official HERO 3107.

Only creates a LOCAL unsigned review candidate. No flash or signing operation.
The original 717 FFS files are independently compared after UEFIExtract parses
the result. ASUS capsule authentication and motherboard dispatch remain untested.
"""
from pathlib import Path
import collections,hashlib,json,re,struct,subprocess,sys
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[1]
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'analysis'))
from inventory import inventory
ORIGINAL=ROOT/'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP'
EXPECTED='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    source=ORIGINAL.read_bytes();assert sha(source)==EXPECTED
    build=json.loads((OUT/'build.json').read_text());verify=json.loads((OUT/'verification.json').read_text())
    driver=(OUT/'USB/EFI/HERO/HeroIpmiM1.efi').read_bytes();assert verify['all_passed'] and verify['driver_sha256']==sha(driver)
    ffs=(OUT/'HeroIpmiSetupM1.ffs').read_bytes();assert build['ffs_sha256']==sha(ffs)
    # Coordinates from this exact official 3107 UEFIExtract dump, not 3001.
    volume=0x12d1000;start=0x1a4c518;end=0x1cc1000
    assert source[volume+40:volume+44]==b'_FVH'
    assert struct.unpack_from('<Q',source,volume+32)[0]==end-volume
    hlen=struct.unpack_from('<H',source,volume+48)[0]
    assert sum(struct.unpack('<'+'H'*(hlen//2),source[volume:volume+hlen]))&65535==0
    assert start%8==0 and len(ffs)<end-start and source[start:end]==b'\xff'*(end-start)
    assert int.from_bytes(ffs[20:23],'little')==len(ffs) and ffs[18]==7 and ffs[23]==0xf8
    header=bytearray(ffs[:24]);header[17]=header[23]=0;assert sum(header)%256==0
    modified=bytearray(source);modified[start:start+len(ffs)]=ffs
    assert modified[:start]==source[:start] and modified[start+len(ffs):]==source[start+len(ffs):]
    candidate=OUT/'HERO-3107-IPMI-M1-UNSIGNED-REVIEW.CAP';data=bytes(modified)
    if candidate.exists() and candidate.read_bytes()!=data:
        old_hash=sha(candidate.read_bytes());archive=OUT/'intermediate'/old_hash[:16];archive.mkdir(parents=True,exist_ok=True)
        # Preserve this task's intermediate build only. Resolve both sides before
        # moving the directory tree; never move outside the M1 workspace.
        for source_path in (candidate,candidate.with_name(candidate.name+'.dump')):
            if source_path.exists():
                dest=archive/source_path.name
                assert source_path.resolve().is_relative_to(OUT.resolve()) and dest.resolve().is_relative_to(OUT.resolve())
                assert not dest.exists();source_path.rename(dest)
    if not candidate.exists():candidate.write_bytes(data)
    dump=candidate.with_name(candidate.name+'.dump')
    if not dump.exists():
        p=subprocess.run([str(ROOT/'tools/UEFIExtract_A75/UEFIExtract.exe'),str(candidate),'all'],cwd=ROOT,capture_output=True,text=True)
        (OUT/'uefiextract-output.txt').write_text(p.stdout+p.stderr,encoding='utf-8');assert p.returncode==0,p.stderr
    modules=inventory(str(candidate.relative_to(ROOT)))
    originals=next(iter(json.loads((ROOT/'analysis/hero_3107_official/inventory.json').read_text()).values()))
    before=collections.Counter((m['guid'],m['sha256']) for m in originals)
    after=collections.Counter((m['guid'],m['sha256']) for m in modules)
    assert not before-after,'Original FFS changed or disappeared'
    added=after-before;assert sum(added.values())==1 and len(modules)==718 and len(originals)==717
    item=next(m for m in modules if m['guid'].lower()==build['ffs_guid'])
    assert item['sha256']==sha(ffs)
    # A75 calls this subtype "UI"; the historical inventory helper only
    # collected the older "User interface" spelling. Verify the actual bytes.
    ui=(ROOT/item['path']/'2 UI section/body.bin').read_bytes().decode('utf-16-le').rstrip('\0')
    assert ui=='HeroIpmiSetupM1'
    assert (ROOT/item['path']/'1 PE32 image section/body.bin').read_bytes()==driver
    assert '72338391' not in ''.join(build['depex']).lower()
    report=dict(original_sha256=EXPECTED,candidate_sha256=sha(data),length=len(data),original_files=717,result_files=718,
      originals_byte_identical=True,added_module=item,changed_interval=[hex(start),hex(start+len(ffs))],changed_range_bytes=len(ffs),
      unchanged_capsule_header=True,unused_space_before=end-start,unused_space_after=end-start-len(ffs),
      caveats=['Original capsule signature is no longer valid for changed firmware contents; not ASUS signed.',
       'UEFIExtract structure/checksums and byte preservation only; not a flashability or Boot Guard verification.',
       'Native ASUS Advanced menu linking and actual DXE dispatch/ReadyToBoot initialization on HERO remain untested.',
       'Use the separate USB package to test HII/configuration/initialization before considering this candidate.'])
    (OUT/'capsule-verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k!='added_module'},indent=2))
if __name__=='__main__':main()
