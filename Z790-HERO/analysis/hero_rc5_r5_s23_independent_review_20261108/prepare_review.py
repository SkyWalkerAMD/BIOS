"""Adapt the independent C04 audit to new C05; never write prior artifacts."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
OLD=ROOT/'analysis/hero_rc5_r5_s22_independent_review_20261108'
replace={
 'hero_ipmi_rc5_s22_20261108':'hero_ipmi_rc5_s23_20261108',
 'RC5-IPMI-ONLY-R5-S22-CANDIDATE04':'RC5-IPMI-ONLY-R5-S23-CANDIDATE05',
 '8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f':'68cfc48a76d41f23edf093984818b64a6b13a686956666339733fe0a84e287f9',
 '554e210cca3de3bc337f944e7126f244d1ffcd67bb81089662f6d3ae78f2ad1b':'15c1e38b0693105a3f2abad917f375cc0d36285d9e4d8402013e5088244766fa',
 'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75':'1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc',
 'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs':'analysis/hero_p6_s23_20261108/HeroIpmiNativeP6.ffs',
 'RC5-R5/S22':'RC5-R5/S23','POSITIVE-FROZEN-R5-S22':'POSITIVE-FROZEN-R5-S23',
}
rows=[]
for name in ('audit_final.py','audit_inventory_absence.py'):
    src=OLD/name;raw=src.read_bytes();text=raw.decode('utf-8')
    for old,new in replace.items():text=text.replace(old,new)
    if name=='audit_final.py':
        at="verdict('NEGATIVE-BASELINE-UNCHANGED',old['cap'])"
        extra="\n c04=ROOT/'analysis/hero_ipmi_rc5_s22_20261108/RC5-IPMI-ONLY-R5-S22-CANDIDATE04/HERO-3107-IPMI-RC5-IPMI-ONLY-R5-S22-CANDIDATE04-UNSIGNED.CAP'\n assert sha(c04.read_bytes())=='8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f'\n verdict('NEGATIVE-PREVIOUS-C04-S22',c04.read_bytes())"
        assert at in text;text=text.replace(at,at+extra)
    else:
        at="APIS=('dfb7ec4e-5499-4812-a2b7-ab6601f4e505','7e06fa9a-532e-44c6-928a-cf19d2718e4b')"
        assert at in text;text=text.replace(at,at[:-1]+",'9412c522-5b86-4cae-8799-82ee194b9fa5')")
    dest=HERE/name;assert not dest.exists();dest.write_text(text,encoding='utf-8')
    rows.append({'original':src.relative_to(ROOT).as_posix(),'original_sha256':hashlib.sha256(raw).hexdigest(),'copy':dest.relative_to(ROOT).as_posix(),'copy_sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
(HERE/'review-source-provenance.json').write_text(json.dumps({'files':rows,'replacements':replace,'additional_cases':['Reject exact previous C04 S22 under rewritten current manifest.','Also scan known I5 trigger protocol GUID.']},indent=2)+'\n',encoding='utf-8')
print('Prepared isolated C05 review; no source firmware or old review changed.')
