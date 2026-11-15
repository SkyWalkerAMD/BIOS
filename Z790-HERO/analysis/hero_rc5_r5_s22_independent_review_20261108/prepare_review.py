"""Adapt this auditor's frozen C03 regression to isolated new C04 evidence."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
OLD=ROOT/'analysis/hero_rc5_r4_s21s_independent_review_20261108'
replace={
 'hero_ipmi_rc5_s21s_20261108':'hero_ipmi_rc5_s22_20261108',
 'RC5-IPMI-ONLY-R4-S21S-CANDIDATE03':'RC5-IPMI-ONLY-R5-S22-CANDIDATE04',
 '7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624':'8adf138c82c71d8d599b625fa5776bcd201096f59d6f357fd2ef75251efdf70f',
 '3b3665040f28e374b0056fd98a7b1b283f6baaeb77067f34e3d701564fb04ed3':'be0d4f23272f8c98266629a9e10b1f36f47c35477eb997b3ce44525d230fc792',
 'a3036261c18bd66b158844a6818cf828b54af002dbb9ecf45d8dbc97a5317b2f':'81494db8d84839ff3d0368765334e22cbc0b27c4fd9c234dcb792d45272484b4',
 'analysis/hero_sensor_r4_20261108/HeroIpmiCoreR4.ffs':'analysis/hero_sensor_r5_20261108/HeroIpmiCoreR5.ffs',
 '75f2f92feaaeccc1eadccf2beda02d7f2d3dc34ffa9058a62928d16009b7a63b':'554e210cca3de3bc337f944e7126f244d1ffcd67bb81089662f6d3ae78f2ad1b',
 '401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66':'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75',
 'analysis/hero_p6_settings21s_20261108/HeroIpmiNativeP6.ffs':'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs',
 'RC5-R4/S21S':'RC5-R5/S22','POSITIVE-FROZEN-R4-S21S':'POSITIVE-FROZEN-R5-S22',
}
rows=[]
for name in ('audit_final.py','audit_inventory_absence.py'):
    src=OLD/name;data=src.read_bytes();text=data.decode('utf-8')
    for old,new in replace.items():text=text.replace(old,new)
    if name=='audit_final.py':
        at="verdict('NEGATIVE-BASELINE-UNCHANGED',old['cap'])"
        extra="\n c03=ROOT/'analysis/hero_ipmi_rc5_s21s_20261108/RC5-IPMI-ONLY-R4-S21S-CANDIDATE03/HERO-3107-IPMI-RC5-IPMI-ONLY-R4-S21S-CANDIDATE03-UNSIGNED.CAP'\n assert sha(c03.read_bytes())=='7a21f28c5a805ea29d651524b2ec2e05925252ff0799b71251583d99e1d53624'\n verdict('NEGATIVE-PREVIOUS-C03-FIXED-BUS',c03.read_bytes())"
        assert at in text;text=text.replace(at,at+extra)
    target=HERE/name
    assert not target.exists(),target
    target.write_text(text,encoding='utf-8')
    rows.append({'original':src.relative_to(ROOT).as_posix(),'original_sha256':hashlib.sha256(data).hexdigest(),
                 'copy':target.relative_to(ROOT).as_posix(),'copy_sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
(HERE/'review-source-provenance.json').write_text(json.dumps({'files':rows,'replacements':replace,
 'additional_case':'Reject complete previous C03 with fixed-bus R4/S21S even under a rewritten current manifest'},indent=2)+'\n',encoding='utf-8')
print('Prepared isolated C04 review; no original source or artifact changed.')
