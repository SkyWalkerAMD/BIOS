"""Record the observed read/check/cancel path, not an unperformed flash."""
from pathlib import Path
import json,hashlib
P=Path(__file__).resolve().parent
ROOT=P.parents[1]
LIVE=ROOT/'analysis/hero_ipmi_flash_live_20261104'
def read(n):return json.loads((LIVE/'responses'/n).read_text(encoding='utf-8'))
assert read('056-power-off-bios.json')['result']['confirmed']
assert read('058-navigate.json')['result']['url'].endswith('#login')
assert read('process.json')['state']=='closed'
screens=['021-capture.png','024-capture.png','031-key-Enter.png','032-key-ArrowRight.png',
         '034-key-Enter.png','039-capture.png','044-key-ArrowDown.png','046-key-Enter.png',
         '049-capture.png','050-key-ArrowRight.png','051-key-Enter.png','053-key-Enter.png','057-capture.png']
evidence=[]
for name in screens:
    data=(LIVE/'screens'/name).read_bytes()
    evidence.append(dict(file='screens/'+name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
record=dict(date='2026-11-04',board='ROG MAXIMUS Z790 HERO',bios='3107',bios_build_date='11/28/2025',
    cpu='Intel Core i9-14900KS',memory_mib=65536,me_firmware='16.1.38.2676',bmc_firmware='1.3.13',
    updater='ASUS EZ Flash 3 Utility v03.00',
    transport=dict(kind='BMC virtual CD exposing a FAT16 volume',same_iso_for_both_files=True,
        iso_sha256='cb2d13c18661ec62e081d456426c482cc7e71537201de4ec85403af06ca33705'),
    candidate=dict(file_on_media='P5RC2.CAP',sha256='5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521',
        read_confirmed=True,accepted=False,message='Selected file is not a proper BIOS!',
        update_confirmation_reached=False,firmware_written=False,rejection_screen='screens/039-capture.png'),
    official_control=dict(file_on_media='ORIG3107.CAP',sha256='e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a',
        read_confirmed=True,accepted_for_update_confirmation=True,model='ROG MAXIMUS Z790 HERO',version='3107',
        selected_no_and_cancelled=True,firmware_written=False,confirmation_screen='screens/049-capture.png',
        no_selected_screen='screens/050-key-ArrowRight.png'),
    interpretation='The same ISO supplied both inputs. RC2 was rejected; the original was accepted for update confirmation. The generic EZ Flash message does not identify its internal failing check. Independent capsule verification establishes a payload signature mismatch, but this is separate from proving the exact runtime branch.',
    flashback=dict(official_control_performed=False,candidate_performed=False,restoration_from_candidate_performed=False,
        reason='Physical operator pending; user requested an offline execution package and manual.'),
    changes=dict(host_powered_on_for_check=True,ctrl_alt_del_used_to_enter_setup=True,bios_settings_changed=False,
        bios_written=False,bmc_firmware_written=False,final_host_power='off'),
    cleanup=dict(key_sequence_stopped=True,virtual_media_unmounted=True,bmc_logged_out=True,private_browser_closed=True),
    interruptions=['First private browser session ended before any host power request; owned browser processes were checked absent. An unfinished command was not replayed on restart.',
        'One power-on request had a JavaScript parse error and did not execute; a corrected explicit request subsequently powered on the observed-off host.'],
    screenshots=evidence)
(P/'live-image-check.json').write_text(json.dumps(record,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps(dict(rc2_ezflash_accepted=False,official_control_accepted=True,bios_written=False,
                     final_host_power='off',flashback_verified=False,screens=len(evidence)),indent=2))
