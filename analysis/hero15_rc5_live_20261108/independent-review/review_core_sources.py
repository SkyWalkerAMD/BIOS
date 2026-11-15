"""Record bounded R4->R5 and S21S->S22 source delta; no rebuild or target access."""
from pathlib import Path
import difflib, hashlib, json
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def rec(path):
    b=path.read_bytes()
    return {'path':path.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

def main():
    pairs=[('R5','hero_sensor_r4_20261108','hero_sensor_r5_20261108',{'driver.c','engine.c','launcher.c','hero_bmc_pci.h'}),
           ('P6-S22','hero_p6_settings21s_20261108','hero_p6_s22_20261108',{'driver.c','transport.c','hero_bmc_pci.h'})]
    rows=[];patch=[]
    for label,old,new,allowed in pairs:
        a=ROOT/'analysis'/old/'source';b=ROOT/'analysis'/new/'source'
        names={p.relative_to(a) for p in a.rglob('*') if p.is_file()}
        newer={p.relative_to(b) for p in b.rglob('*') if p.is_file()}
        assert not names-newer, 'removed source'
        changed=[];unchanged=[]
        for name in sorted(newer):
            x,y=a/name,b/name
            if x.exists() and x.read_bytes()==y.read_bytes():unchanged.append(rec(y));continue
            assert name.as_posix() in allowed,('unexpected source change',name)
            changed.append(rec(y))
            patch.extend(difflib.unified_diff(x.read_text().splitlines(True) if x.exists() else [],y.read_text().splitlines(True),fromfile=str(x),tofile=str(y)))
        assert {Path(x['path']).name for x in changed}==allowed
        if label=='R5':
            x=(a/'engine.c').read_text().split('static int ready(void)',1)[1]
            y=(b/'engine.c').read_text().split('static int ready(void)',1)[1].replace('R5_','R4_').replace(
                'Expected exactly one validated ASPEED management device at segment0/dev1/fn0 with valid BAR1; see PCI discovery log.',
                'Expected one ASPEED 1A03:2402 rev 01 at 0000:04:01.0 with valid BAR1.')
            assert x==y,'R5 logic after PCI helpers changed beyond log labels'
            assert (b/'driver.c').read_text().replace('R5','R4')==(a/'driver.c').read_text()
        else:
            x=(a/'transport.c').read_text().split('static int ready(void)',1)[1]
            y=(b/'transport.c').read_text().split('static int ready(void)',1)[1]
            # The remaining transport diff is solely its diagnostic rejection text.
            xlines=x.splitlines(True);ylines=y.splitlines(True)
            rest=list(difflib.unified_diff(xlines,ylines))
            assert all(not line.startswith(('+','-')) or line.startswith(('+++','---')) or
                       ('discover()' in line and 'result(' in line) for line in rest),rest
            expected=(a/'driver.c').read_text().replace('HERO-IPMI-P6-S21S / synchronous AfterBoot refresh / settings unchanged',
                'HERO-IPMI-P6-S22 / dynamic PCI discovery / S21S lifecycle unchanged')
            assert expected==(b/'driver.c').read_text()
        rows.append({'core':label,'changed':changed,'unchanged':unchanged,
                     'non_selection_logic_preserved':True})
    h1=ROOT/'analysis/hero_sensor_r5_20261108/source/hero_bmc_pci.h'
    h2=ROOT/'analysis/hero_p6_s22_20261108/source/hero_bmc_pci.h'
    assert h1.read_bytes()==h2.read_bytes()
    (HERE/'portable-core-source-differences.patch').write_text(''.join(patch),encoding='utf-8')
    out={'passed':True,'rows':rows,'shared_policy':rec(h1),
         'actual_pe_checks':rec(HERE/'portable-core-actual-pe-review.json'),
         'observations':[
          'All matching VID/DID functions are counted before strict class/subsystem/descriptor filtering; incomplete enumeration rejects.',
          'Only bus numbering is dynamic. Segment0, device1, function0, revision1, type0, class0C0701 and subsystem1A03:2402 remain mandatory.',
          'Every KCS access repeats selected config identity/BAR checks. Only Command bit1 may be changed and restored.',
          'Firmware-owned PCI protocol/resource buffers remain trusted service output in production cores; the .15 launcher additionally bounds them with GetMemoryMap.',
          'R5 OEM/RPM/SDR/locks/Dashboard and S22 settings/HII/AfterBoot lifecycle are unchanged from previous reviewed versions.'
         ],
         'permission_boundary':'Core-only code review passed. Host15 launcher/ISO, real UEFI BDF, native forms, new CAP and FlashBack remain separately gated.',
         'no_hardware_actions':True,'frozen_previous_artifacts_modified':False}
    (HERE/'portable-core-source-review.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'passed':True,'report':rec(HERE/'portable-core-source-review.json')},indent=2))
if __name__=='__main__':main()
