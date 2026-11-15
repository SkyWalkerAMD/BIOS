"""Reuse this auditor's frozen prior loader checks against new pinned .15 PE.
The additional cases use independently parsed actual .15 DMI. Offline only.
"""
from pathlib import Path
import hashlib, json, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
prior=ROOT/'analysis/hero_p6_s21s_independent_review_20261108/test_ramcheck4_final.py'
text=prior.read_text(encoding='utf-8')
changes={
 'ROOT=OUT.parents[1]':'ROOT=OUT.parents[2]',
 'analysis/hero_p6_ramcheck4_20261108':'analysis/hero_p6_ramcheck15_s22_20261108',
 'analysis/hero_p6_settings21s_20261108':'analysis/hero_p6_s22_20261108',
 'ad88d5ec533b65b3b2b983490e62afcdc1f05ea067cb23cbda85eaa2a8e3899c':'b88956710791758693b140d535be6f2ca6284b62fa70001b47e342c005f79d09',
 'e982ff36f2eedd7bd5be710c2562546d23da61ed9e7c524d60d90d5fae2355b8':'d6cfd15e23b08fddc80f060e807b8ba472db7bb5c8486eaccba226d9b2a8e3b2',
 '401a61dbf60f128a1f0aba86462aa90ce6e69a95f4266c64876072a841672b66':'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75',
 'HERO-P6-RAMCHECK-4.iso':'HERO-P6-HOST15-S22.iso',
 'ramcheck4-final-independent.json':'host15-s22-loader-base-checks.json',
}
for a,b in changes.items():
    assert a in text,a
    text=text.replace(a,b)
env={'__file__':str(HERE/'review_s22_loader.py'),'__name__':'independent_reused_checks'}
exec(compile(text,str(prior),'exec'),env)
Machine=env['Machine'];DEFAULT=env['DEFAULT']
raw=(HERE.parent/'host-DMI.bin').read_bytes()
entry=(HERE.parent/'host-smbios_entry_point.bin').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='9831e487a7a77ea5ff841e53ab36ff3474b56aa8a328d2a467c578a7a2859637'
pos=0;ident=0
while pos<len(raw):
    kind,n=raw[pos],raw[pos+1]
    if kind==1:ident=pos;break
    pos=raw.index(b'\0\0',pos+n)+2
assert ident and raw[ident+8:ident+24].hex()=='46f522b2b3dbc89abbfb581122d8be9f'
rows=[]
for case in ('actual15_safe21','actual15_safe32','uuid_canonical_bytes_wrong_endian','old71_uuid','uuid_changed_before_L','no_L'):
    data=bytearray(raw)
    if case=='uuid_canonical_bytes_wrong_endian':data[ident+8:ident+24]=bytes.fromhex('b222f546dbb39ac8bbfb581122d8be9f')
    if case=='old71_uuid':data[ident+8:ident+24]=bytes.fromhex('9565299beb5589e65fd208bfb8eeda44')
    keys='QQ' if case=='no_L' else 'LQQ'
    m=Machine(DEFAULT if case=='actual15_safe32' else DEFAULT[:21],keys=keys)
    m.u.mem_write(m.base+0x7000,bytes(data));ep=bytearray(entry)
    struct.pack_into('<IQ',ep,12,len(data),m.base+0x7000);ep[5]=0;ep[5]=(-sum(ep))&255
    m.u.mem_write(m.base+0x6100,bytes(ep))
    if case=='uuid_changed_before_L':
        def drift(machine,name,count):
            if name=='HeroIpmiState' and count==1:
                machine.u.mem_write(machine.base+0x7000+ident+8,b'\0')
        m.mutate=drift
    output=m.run();expected=1 if case.startswith('actual15_') else 0
    assert m.calls.count('Load')==m.calls.count('Start')==expected,(case,output[-2000:])
    assert not any(x.startswith('Forbidden') for x in m.calls)
    rows.append({'case':case,'passed':True,'loads':expected})
base=json.loads((HERE/'host15-s22-loader-base-checks.json').read_text())
report={'passed':True,'base_cases':base['cases'],'additional_actual_dmi_cases':len(rows),'rows':rows,
        'launcher_sha256':base['launcher_sha256'],'iso_sha256':base['iso_sha256'],'core_sha256':base['core_sha256'],
        'reuse_source_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
        'source_scope':'App/preflight/loading order unchanged from reviewed RAMCHECK4; only branding, QR prefix, exact raw .15 UUID and embedded S22 pin changed.',
        'permitted':'One explicit .15 RAM loading experiment after fresh safe-default UEFI preflight; parent controls hardware.',
        'remaining_limits':['Actual UEFI PCI bus and exact P6 form resource still need hardware evidence.',
                            'No claim of old C03 payload equivalence, new CAP flashing, initial native DXE/SetupEnter, F10 configuration writes or recovery.'],
        'no_hardware_actions':True}
(HERE/'host15-s22-loader-review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'passed':True,'cases':base['cases']+len(rows),'iso_sha256':base['iso_sha256'],
                  'report_sha256':hashlib.sha256((HERE/'host15-s22-loader-review.json').read_bytes()).hexdigest()}))
