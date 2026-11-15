"""Update the project index while retaining the previous ACE release history."""
from pathlib import Path
import datetime, json

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
def read(p):return json.loads(p.read_text(encoding='utf8'))
def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf8')

def main():
    delivery=read(HERE/'bios_delivery.json')
    manifest=read(Path(delivery['directory'])/'manifest.json')
    identity=read(HERE/'remote_172_20_2_162/identity_summary.json')
    review=HERE/'review';review.mkdir(exist_ok=True)
    req=read(BASE/'requirements.json')
    snapshot=review/'prior_root_requirements.json'
    if not snapshot.exists():save(snapshot,req)
    history=req.setdefault('target_history',{})
    if req.get('active_target')=='W790_ACE_1904':
        history['W790_ACE_1904']={'candidate':req.get('current_password_lock_candidate'),
            'release':req.get('experimental_bios_release'),
            'hardware_scope':req.get('password_lock_hardware_validation_scope')}
    req['active_target']='W790E_SAGE_SE_1904'
    req['priority_order']=['W790E_SAGE_SE_1904','W790_ACE_1904','W790_SAGE_2003','W790_ACE_2003','W890_SAGE_0603']
    req['priority_updated_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    req['confirmed_by_user']['prioritize_w790_ace_1904']=False
    req['confirmed_by_user']['prioritize_w790e_sage_se_1904']=True
    req['confirmed_by_user']['maintenance_authorization_scope']='Prior ACE host maintenance only. New SAGE host: read-only identity; no power/boot/media/flash changes this turn.'
    req['implementation_status']=delivery['status']
    req['modified_cap_created']=True
    req['password_lock_hardware_validated']=False
    req['password_lock_baseline_hardware_validated']=False
    req['password_lock_hardware_validation_scope']='Current SAGE SE target: BMC inventory only, no lock execution. Historical ACE validation retained in target_history.'
    req['experimental_bios_release']=delivery
    req['current_password_lock_candidate']={
        'target':manifest['target'],'status':delivery['status'],'priority':'highest',
        'driver_sha256':manifest['driver_sha256'],'candidate_sha256':manifest['capsule_sha256'],
        'password_lock_code_implemented':True,'firmware_review_image_created':True,
        'hardware_password_lock_validated':False,'persistent_hardware_password_lock_validated':False,
        'signed_flash_package_created':False,'physical_firmware_writes_performed':False,
        'validation':manifest['test_counts'],'report':str(Path(delivery['directory'])/'验证报告.html'),
        'source_directory':str(HERE),'bmc_identity':identity,
        'limits':['Unsigned modified payload; update-tool acceptance and recovery unknown.',
                  'ASUS complete boot, automatic dispatch, direct Del/F2, private graphical/EZ/search paths unverified.',
                  'SAGE hardware password operation and persistent NVRAM/defaults/training unverified.']}
    req['next_required_external_evidence']='For SAGE SE1904: runtime module fingerprints and controlled no-flash tests; confirm recoverable backup/update path before any firmware flashing.'
    req['deferred_targets']=['W790_ACE_1904','W790_SAGE_2003','W790_ACE_2003','W890_SAGE_0603']
    save(BASE/'requirements.json',req)
    save(BASE/'priority.json',{'active_target':req['active_target'],'priority_order':req['priority_order'],
         'current_release':delivery,'original_scope_preserved':True,'flashing_performed':False})
    print(json.dumps({'active_target':req['active_target'],'release':delivery['zip'],'history_preserved':True}))

if __name__=='__main__':main()
