from pathlib import Path
import hashlib
import json

HERE=Path(__file__).resolve().parent
F05=HERE.parent
ROOT=F05.parents[3]
def ref(p):
    b=p.read_bytes()
    return {'path':p.relative_to(ROOT).as_posix(),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}

manual=HERE/'E22143_Pro_WS_W790-ACE_UM_V3_WEB.pdf'
assert ref(manual)['sha256']=='5f7d566a19bccf10eea395986e9439ebf1f7a9f576b2e56b0d9b08fd76f2a4d3'
prior=[
    ('ACE EXP01',ROOT/'W790-ACE-1904-AiTweaker密码BIOS-EXP01/说明-先读.txt',
     'Use model/version/hash-bound manifests and distinguish RAM/OVMF coverage from an installed image.',
     'Older fd5c6ffc CAP and eb4d9b43 driver are different bytes. Its retained original signature was invalid for its changed payload, and FlashBack was untested. Neither old acceptance assumptions nor recovery-access limits transfer to the current physical-FlashBack plan.'),
    ('W790E-SAGE EXP02',ROOT/'W790E-SAGE-SE-1904-AiTweaker密码BIOS-EXP02-UNSIGNED/说明-先读.txt',
     'Keep exact artifact identities and separate hardware RAM observations from flash acceptance.',
     'SAGE board, AMITSE addresses, image, file name, port layout and validation are not ACE evidence. This archived package explicitly lacked completed FlashBack testing.'),
    ('W790E-SAGE recovery references',ROOT/'analysis/aitweaker_lock/lock_sage_1904/review/flash_readiness/remote_only/vendor_recovery_review.json',
     'Distinguish a physical FlashBack procedure from virtual-media or BMC updater recovery.',
     'Its PWW790SG.CAP naming, ASMB11 backend, board connector map and then-current remote-only constraint do not apply to ACE. The user now intends onsite FlashBack after packaging.'),
    ('W890 0603 release review',ROOT/'analysis/aitweaker_lock/lock_w890_sage/release_review/W890-0603-发布检查.txt',
     'Make unsupported acceptance/preservation claims explicit; a listed feature is not an executed acceptance test.',
     'W890 BIOS region/layout, capsule flags 0x10005, signatures, AST2600/BMC 2.01.11, file names and lack of onsite access are unrelated proof for ACE. No FlashBack acceptance was demonstrated by this reviewed document.'),
    ('HERO F1 field package',ROOT/'analysis/hero_ipmi_flash_validation_20261104/field-package/00-START/快速执行顺序.txt',
     'Distinct candidate/recovery media labels, exact hashes, single root CAP, and a simple record of LED state/time/POST/functions prevent file confusion.',
     'MZ790H.CAP, 32MiB payload, HERO ports/firmware and its RC2 EZ Flash refusal cannot be transplanted. The archived package says FlashBack was not yet executed; its proposed official-control/experimental/recovery sequence is not evidence that any stage passed and is not a new requirement to perform an extra official flash here.'),
    ('HERO evidence boundaries',ROOT/'analysis/hero_ipmi_flash_validation_20261104/field-package/04-CURRENT-EVIDENCE/验证记录与剩余项.txt',
     'A completed LED sequence/version display and successful official update do not by themselves prove modified feature behavior or tested recovery.',
     'HERO SMM/capsule analysis does not analyze the independent ACE FlashBack controller. Do not turn an earlier proposed field procedure into actual success.'),
    ('Prior ACE layout/recovery note',F05/'layout_recovery/README-布局与恢复.txt',
     'Public official CAP is not the current machine full-SPI readback; preserve personalization limitations.',
     'Its older embedded-driver/hash discussion and historical only-BMC access describe that earlier review. The latest explicit user plan to prepare an onsite FlashBack package supersedes the physical-access constraint; the frozen older report is left unchanged.')
]

report={
 'schema':'ace1904_flashback_instructions_review_v1',
 'status':'OFFICIAL_PROCEDURE_AND_ARCHIVED_PACKAGING_PRACTICES_REVIEWED_NO_HARDWARE_ACTION',
 'review_date':'2026-11-08',
 'scope':{'board':'ASUS Pro WS W790-ACE','route':'Onsite motherboard USB BIOS FlashBack',
          'user_direction':'Prepare the package now; onsite physical operation later.',
          'final_cap_selection':'Owned by root/packaging agent; this review neither selects nor modifies the CAP.',
          'bmc_or_other_hardware_access_performed':False,'usb_format_performed':False,'flash_performed':False,
          'external_messages_sent':False},
 'official_sources':[
   {'title':'Pro WS W790-ACE User Manual E22143, Revised Edition V3, June 2023',
    'url':'https://dlcdnets.asus.com/pub/ASUS/mb/LGA4677/Pro_WS_W790-ACE/E22143_Pro_WS_W790-ACE_UM_V3_WEB.pdf?model=Pro+WS+W790-ACE',
    'file':ref(manual),'pages':82,
    'relevant_pages':[{'section':'2.2 BIOS update utility','printed_page':'2-19','pdf_page_number_1based':55,'pdf_page_index_0based':54,'visual_review_completed':True,'render':ref(HERE/'manual-page55-printed2-19.png')},
                      {'section':'2.3.1 Rear I/O connection','printed_page':'2-21','pdf_page_number_1based':57,'pdf_page_index_0based':56,'visual_review_completed':True,'render':ref(HERE/'manual-page57-printed2-21.png')}],
    'verified_facts':['Required filename PWW790A.CAP; optional official BIOSRenamer performs naming.',
                      '24-pin connected, PSU on and host not booted; use dedicated rear USB port and physical FlashBack button.',
                      'Hold about three seconds until three LED flashes; wait for completion with LED off.',
                      'Five-second flashing followed by a steady light is an abnormal result; avoid USB/power/host-on/Clear-CMOS interruption.']},
   {'title':'ASUS China support FAQ 1038568: USB BIOS FlashBack','url':'https://www.asus.com.cn/support/faq/1038568/',
    'observed_updated_date':'2024-12-13','reviewed_via_web':True,
    'relevant_web_line_ranges':['27-31','68-105','112','149-167'],
    'verified_facts':['At least 1GB USB; FAT16/32 MBR and one partition; put the correctly renamed CAP in the root directory.',
                      'Keep host shut down with power available; no power/USB interruption or Clear CMOS during work.',
                      'About eight minutes is a generic estimate; not an automatic timeout or permission to interrupt.',
                      'Format/name/model are first checks for the steady-light error; inspect BIOS after completion.'],
    'scope_limit':'Generic FAQ uses another board as an example. W790-ACE-specific file name, port and power wording come from its own manual. Intel 800-series-specific ME advice is not copied to this W790 procedure.'}
 ],
 'visual_port_review':{
    'view_orientation':'Rear I/O facing the viewer, audio jacks at right as in manual.',
    'dedicated_usb':'Second of the two four-port black USB stacks from the left; second port down from its top, enclosed by the red box on printed page 2-19.',
    'button':'Far-left lower button with BIOS marking; upper button is Clear CMOS. Rear-I/O legend numbers them 6 and 1 respectively.',
    'instruction_limit':'Use the actual board markings plus the manual image. No reliance on color alone or an inferred per-port electrical number.'},
 'package_instruction_decisions':{
    'recommended_usb':'FAT32, MBR, single partition, at least 1GB; formatting only later by the onsite operator after preserving their files.',
    'rename_is_not_authentication':'PWW790A.CAP is a discovery name, not proof that the controller accepts the candidate.',
    'two_media_optional':'If an official recovery image is supplied, label and separate it from candidate media. Do not mix identically named files; compare SHA-256.',
    'no_additional_official_flash_required_by_this_review':True,
    'bmc_spi_cable_required_for_this_route':False,
    'route_distinction':'FlashBack uses the motherboard physical USB/controller/button path; the earlier expansion-card BMC Prepare failure does not make the BMC TPM/SPI ribbon a prerequisite.',
    'no_claim_of_candidate_acceptance_or_recovery':'Actual ACE FlashBack acceptance, cold boot, password behavior and an executed recovery are still onsite observations. These do not prevent packaging the explicitly requested onsite candidate.',
    'preservation_limit':'Do not import BMC normal-update preservation ranges into FlashBack. Machine-specific state and custom splash preservation have not been established for this controller.',
    'same_version_limit':'1904 alone cannot distinguish preexisting firmware from a modified 1904-base image.'},
 'prior_project_reviews':[{'label':label,'source':ref(p),'reusable_practice':practice,'must_not_transfer':limit} for label,p,practice,limit in prior],
 'draft':ref(HERE/'现场操作说明-草案.txt'),
 'review_method':'Official web lookup, byte-bound local PDF download, Poppler rendering at 140dpi and actual image inspection of complete relevant pages; read-only selected prior project documents. No firmware code or hardware execution.',
 'limitations':['This is instructions review, not independent FlashBack-controller reverse engineering or a guarantee of accepting an engineered/self-signed capsule.',
                'Old remote-only access statements remain historical evidence; current onsite-plan scope is recorded here without rewriting them.',
                'No whole-machine full-SPI backup or all-failure recovery guarantee is created by including an official recovery CAP.']
}
out=HERE/'flashback_instructions_review.json'
out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(json.dumps({'status':report['status'],'report':ref(out),'draft':report['draft']},ensure_ascii=False))
