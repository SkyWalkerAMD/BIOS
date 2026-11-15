"""Download and validate the target's official 3107 CAP for offline comparison."""
from pathlib import Path
import hashlib,json,urllib.request,zipfile,io
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'analysis/hero_3107_official'
NAME='ROG-MAXIMUS-Z790-HERO-ASUS-3107'
URL='https://dlcdnets.asus.com/pub/ASUS/mb/BIOS/'+NAME+'.zip'
PUBLISHED='4cf91764f545cb8bb4081bdc5b4d3a48f25d42f35e7610e925d03fa56c389454'

def sha(b):return hashlib.sha256(b).hexdigest()

def main():
    # This path and digest were read from the already saved official support
    # HTML, not guessed from a version string or a third-party mirror.
    support=(ROOT/'analysis/asus_hero.html').read_text(encoding='utf-8')
    assert '/pub/ASUS/mb/BIOS/'+NAME+'.zip' in support and PUBLISHED.upper() in support
    OUT.mkdir(parents=True,exist_ok=True)
    archive=OUT/(NAME+'.zip')
    data=archive.read_bytes() if archive.exists() else urllib.request.urlopen(URL,timeout=45).read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert z.testzip() is None
        matches=[n for n in z.namelist() if n.lower()==(NAME+'.cap').lower()]
        assert len(matches)==1,z.namelist()
        cap=z.read(matches[0])
    assert PUBLISHED in (sha(data),sha(cap)),('ASUS published digest mismatch',sha(data),sha(cap))
    assert len(cap)==33558528 and cap[0x1000+0x10:0x1000+0x14]==bytes.fromhex('5aa5f00f')
    path=OUT/(NAME+'.CAP')
    if path.exists():assert path.read_bytes()==cap
    else:path.write_bytes(cap)
    if not archive.exists():archive.write_bytes(data)
    result=dict(source=URL,support_page='https://www.asus.com/us/supportonly/rog%20maximus%20z790%20hero/helpdesk_bios/',
        supporting_html_sha256=sha((ROOT/'analysis/asus_hero.html').read_bytes()),
        zip_sha256=sha(data),cap_sha256=sha(cap),published_sha256=PUBLISHED,
        published_digest_matches='ZIP' if PUBLISHED==sha(data) else 'CAP',
        cap_bytes=len(cap),purpose='Offline 3107 EC/HWM comparison only. No firmware executed or flashed.')
    (OUT/'source.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
