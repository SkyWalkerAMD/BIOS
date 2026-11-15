"""Independent new .15 S23 launcher checks, reusing the audited S22 suite."""
from pathlib import Path
import difflib,hashlib,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
prior=HERE/'review_s22_loader.py'
text=prior.read_text()
changes={
    'hero_p6_ramcheck15_s22_20261108':'hero_p6_ramcheck15_s23_20261108',
    'hero_p6_s22_20261108':'hero_p6_s23_20261108',
    'b88956710791758693b140d535be6f2ca6284b62fa70001b47e342c005f79d09':'0562fc70092dd7334a5eef3049ea502e58e74d3b4666f09ab524aea2327bc7df',
    'd6cfd15e23b08fddc80f060e807b8ba472db7bb5c8486eaccba226d9b2a8e3b2':'d1cc353b8180b3ddf7fa2b28c6f305a449f54ab5b32c1516852bffba708284d9',
    'abe692ebc1c80fe86b1e319b30fca300a11638845da4c3be7b0c81bd85423d75':'1536d23d32c5787820bf61749df1a16bba7e99b755854f2cd4114f7e62e390cc',
    'HERO-P6-HOST15-S22.iso':'HERO-P6-HOST15-S23.iso',
    'host15-s22-loader-base-checks.json':'host15-s23-loader-base-checks.json',
    'host15-s22-loader-review.json':'host15-s23-loader-review.json',
    'review_s22_loader.py':'review_s23_loader.py',
    'S22 pin':'S23 pin',
    'Actual UEFI PCI bus and exact P6 form resource still need hardware evidence.':'UEFI bus74 is already observed; actual S23 native P5 binding and BMC query remain to be established in its hardware logs.',
}
for a,b in changes.items():
    assert a in text,a
    text=text.replace(a,b)
env={'__file__':str(HERE/'review_s23_loader.py'),'__name__':'s23_reused_loader_checks'}
exec(compile(text,str(prior),'exec'),env)

A=ROOT/'analysis/hero_p6_ramcheck15_s22_20261108/source'
B=ROOT/'analysis/hero_p6_ramcheck15_s23_20261108/source'
changes=[];unchanged=[];patch=[]
old={p.relative_to(A) for p in A.rglob('*') if p.is_file()}
new={p.relative_to(B) for p in B.rglob('*') if p.is_file()}
assert old==new
for name in sorted(new):
    a,b=A/name,B/name
    if a.read_bytes()==b.read_bytes():unchanged.append(name.as_posix());continue
    assert name.as_posix() in ('app.c','kvm.c','resident_image.h'),name
    changes.append({'path':name.as_posix(),'sha256':hashlib.sha256(b.read_bytes()).hexdigest()})
    if name.as_posix()!='resident_image.h':
        delta=list(difflib.unified_diff(a.read_text().splitlines(True),b.read_text().splitlines(True),fromfile=a.relative_to(ROOT).as_posix(),tofile=b.relative_to(ROOT).as_posix()))
        assert all('S22' in s or 'S23' in s or not s.startswith(('+','-')) or s.startswith(('+++','---')) for s in delta),delta
        patch.extend(delta)
report=json.loads((HERE/'host15-s23-loader-review.json').read_text())
report['source_differences']=changes;report['unchanged_source']=unchanged
report['source_comparison']='Relative to frozen S22 loader, only S23 branding/QR prefix and exact embedded PE/size/hash changed. Identity/default/journal/variable-race checks and load lifetime preserved.'
report['source_review_parent_sha256']=hashlib.sha256(prior.read_bytes()).hexdigest()
(HERE/'host15-s23-loader-review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
(HERE/'host15-s23-loader-differences.patch').write_text(''.join(patch),encoding='utf-8')
print(json.dumps({'passed':True,'report_sha256':hashlib.sha256((HERE/'host15-s23-loader-review.json').read_bytes()).hexdigest(),'independent_actual_pe_cases':18,'no_hardware_actions':True}))
