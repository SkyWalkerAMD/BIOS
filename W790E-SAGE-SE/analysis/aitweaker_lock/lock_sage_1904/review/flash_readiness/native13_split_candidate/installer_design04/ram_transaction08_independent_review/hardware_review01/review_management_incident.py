"""Bind captured TX08 first-M prompt and non-return observation, offline only."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
HERE=Path(__file__).resolve().parent;D04=HERE.parents[1];ROOT=next(p for p in HERE.parents if(p/'tools/kvm-pydeps').is_dir())
sys.path.insert(0,str(ROOT/'tools/kvm-pydeps'))
from PIL import Image
HW=ROOT/'analysis/aitweaker_lock/lock_sage_1904/remote_172_20_2_162'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
bound=lambda p:{'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
 prior=HERE/'mode2_hardware-native13-ram-test08-1793715646283-8c2b8643_review.json';r=json.loads(prior.read_text())
 assert sha(prior)=='cbd31152d17adb7af58cee9ae7decce111811cf76bfe74c1a3112864cc8e2feb'
 assert r['status']=='MODE2_PHYSICAL_PROVIDER_ATTACH_READY_REPORTED_PASS'
 images=[];pixels=[]
 for n in [376,377,378]:
  p=HW/f'screen-{n}-current.png'
  with Image.open(p)as im:
   assert im.size==(1600,1200);pixel=im.convert('RGB').tobytes();pixels.append(pixel)
   images.append({**bound(p),'dimensions':list(im.size),'rgb_pixels_sha256':hashlib.sha256(pixel).hexdigest()})
 assert images[1]['sha256']==images[2]['sha256']=='503b195245166a3eba8673aa6bd83b530583bfe7d65db16ceb1cfe287c447e72'
 assert pixels[1]==pixels[2]
 keypath=HW/'native-test11-key-1793715715877-68d82412-result.json';key=json.loads(keypath.read_text())
 assert key['key']=='m' and key['key_sent']is True and key['automatic_retry']is False
 assert key['observed_stage']=='SAGE_NATIVE13_RAM_TEST08_SESSION' and sha(HW/key['evidence'])==key['evidence_sha256']
 offpath=HW/'ram-test11-off-1793715847745-c8e936d1-result.json';off=json.loads(offpath.read_text())
 assert off['action']=='ForceOff'and off['status']==202 and off['automatic_retry']is False
 assert off['powered_off_readback_pending']is True and off['evidence_sha256']==images[-1]['sha256']
 assert json.loads(off['body'])['Id']=='33'
 readbackpath=HW/'manager-restart08-capability-1793715873128.json';readback=json.loads(readbackpath.read_text())
 assert readback['utc']>off['utc']>key['utc']
 assert readback['system']['status']==200 and readback['system']['PowerState']=='Off' and readback['system']['BiosVersion']=='1904'
 assert readback['power']['status']==200 and readback['power']['data']['power_status']==0
 ui=D04/'provider14_chrome07/source/ui.c'
 assert sha(ui)=='5109ed21fb415ac05094549534e459fcbd095eae26e104fa3b703a2e06a35430'
 result={'status':'TX08_MODE2_ATTACH_PASS_FIRST_MANAGEMENT_DISPLAY_RETURN_UNACCEPTED','utc':datetime.now(timezone.utc).isoformat(),
  'device_calls_by_reviewer':0,'frozen_candidate_or_source_evidence_modified':False,
  'last_complete_snapshot':{'review':bound(prior),'snapshot_id':r['snapshot_id'],'bytes':r['bytes'],'crc32':r['crc32'],'sha256':r['sha256'],
    'scope':'Successful exact provider attach and pre-M protected-store match only. It ends before management action.'},
  'management_key':{**bound(keypath),'utc':key['utc'],'key':'m','one_recorded_send':True,'evidence':bound(HW/key['evidence'])},
  'directly_inspected_screens':images,
  'visual_observations':[
   'Screen376 displays a blue console panel headed Ai Tweaker - independent password; ESC cancels. Unlock lasts only for this BIOS session.',
   'The visible message is Set an independent password under Security first. followed by Press any key to return.',
   'Screens377 and378 display the same panel and are byte-identical PNGs with equal decoded RGB pixels. They do not show the expected three-action management form or resident RAM-test menu.'
  ],
  'operator_observations_not_independently_instrumented':[
   'Parent reports one Escape after screen376, with screen377 immediately afterward and screen378 later.',
   'Parent reports no password fixture creation, password text, Enter, B/original Setup, or password-setting action.',
   'No post-M complete Q snapshot or application-return log was obtained. There is no separate exported Escape-send record bound by this review.'
  ],
  'source_correlation':{'source':bound(ui),'line':69,
   'meaning':'The frozen provider has the same AP_UNCONFIGURED message in status_message; ensure_unlocked at lines80-81 prints the matching heading and unconfigured notice. This supports a text/source correlation only, not an internal execution trace, native caller identification or number of prompt entries.'},
  'power_evidence':{'forceoff':bound(offpath),'request_utc':off['utc'],'http_status':202,'task_id':'33','later_readback':bound(readbackpath),'readback_utc':readback['utc'],
   'redfish_power':'Off','native_power':0,'private_credential_cleanup_proven':False,'runtime_twelve_site_rollback_proven':False,
   'media_at_readback':readback['media']},
  'accepted_results':{'initial_preflight':True,'mode1_twelve_site_rollback':True,'mode2_provider_ready_attach':True,'management_three_action_display':False,'management_return':False,
   'hardware_password_actions':False,'permanent_lock':False,'firmware_flash_ready':False},
  'limits':[
   'Unchanged screenshots after a reported Escape do not distinguish key delivery/consumption, a repeated prompt, a wait, native state, firmware stall or KVM caching. No CPU-hold diagnosis is made.',
   'The new observed prompt differs from the prior TX05 black screen, but neither a unique improvement cause nor the exact remaining cause is proven.',
   'The last complete log precedes M; its zero warnings/READY/store match cannot be extended to M return, credential cleanup, runtime target restoration or later variable state.',
   'No password input does not itself prove zero OEM/provider NVRAM effects. A separate new-boot observation is needed for current private absence and original identity.',
   'ForceOff acknowledgment is separated from the later actual Off observations. The Off readback still has CD session129, so this record does not claim media cleanup or end of the entire maintenance session.',
   'Further management/password retries on this unchanged candidate are not accepted by this incident evidence; offline diagnosis and any new candidate require separate review.'
  ],'bindings':[bound(HERE/'review_snapshot.py'),bound(Path(__file__)),bound(HW/'operations/native_test_keys11.mjs'),bound(HW/'operations/power_off_ram_test11.mjs')]}
 out=HERE/'management_first_attempt_incident_review.json';assert not out.exists();out.write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
 print(json.dumps({'status':result['status'],'report':str(out),'sha256':sha(out),'off_readback_utc':readback['utc']}))
if __name__=='__main__':main()
