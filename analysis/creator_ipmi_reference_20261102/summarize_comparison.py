"""Compare retained GET responses. No host or BMC writes and no credentials required."""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent
def read(name):return json.loads((OUT/name).read_text(encoding='utf-8'))
def creator(name):
    r=read('responses/'+name+'.json');assert r['ok'];return r['result']
def hero(name):return read('hero-current/'+name+'.json')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

bios=creator('019-bios-attributes')
registry=creator('027-bios-registry-content')
assert bios['status']==registry['status']==200
attributes=bios['body']['Attributes']
definitions=registry['body']['RegistryEntries']['Attributes']
ipmi=[a for a in definitions if a['AttributeName'].startswith('IPMI')]
assert len(attributes)==373 and len(ipmi)==30
assert {a['AttributeName'] for a in ipmi}=={k for k in attributes if k.startswith('IPMI')}
# Attribute values are unnecessary for the comparison; never export password values.
fields=['AttributeName','DisplayName','Type','ReadOnly','HelpText','Value','LowerBound','UpperBound','ScalarIncrement','MinLength','MaxLength']
reference={
    'source_bios':'ProArt Z790-CREATOR WIFI IPMI 3002',
    'registry':bios['body']['AttributeRegistry'],
    'note':'Definitions only. No live settings or credentials. These identifiers are not HERO Setup offsets.',
    'attributes':[{k:a[k] for k in fields if k in a} for a in ipmi]
}
(OUT/'Creator-IPMI-属性定义.json').write_text(json.dumps(reference,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

thermal=creator('016-thermal');power=creator('017-power')
assert thermal['status']==power['status']==200
target_names=['CPU Temperature','MB Temperature','CPU Package Temp','VRM Temperature','CPU Core Voltage','DRAM VDDQ Volt.','CPU iGPU Volt.','CPU Input Volt.']
target_values=[]
for key,metric,result in [('Temperatures','ReadingCelsius',thermal),('Voltages','ReadingVolts',power)]:
    for s in result['body'][key]:
        if s['Name'] in target_names:
            assert s['Status']['State']=='Enabled' and s.get(metric) is not None
            target_values.append(dict(name=s['Name'],reading=s[metric],metric=metric))
assert len(target_values)==8
pump=next(x for x in thermal['body']['Fans'] if x['Name']=='MB_AIO_PUMP')
assert pump['Status']['State']=='Enabled' and pump['Reading']>0
h_system,h_bios,h_thermal,h_power,h_processors,h_memory=[hero(n) for n in ['system','bios','thermal','power','processors','memory']]
assert h_bios['status']==404
assert h_processors['body']['Members']==h_memory['body']['Members']==[]
assert all(x['Name'] not in target_names for x in h_thermal['body']['Temperatures']+h_power['body']['Voltages'])
dashboard=creator('031-dashboard-final')['text']
assert 'ProArt Z790-CREATOR WIFI' in dashboard and '3002' in dashboard and '1.3.13' in dashboard
assert creator('033-logout')['url'].endswith('/#login')
assert creator('034-stop-browser')['stopping'] is True
comparison={
    'date':'2026-11-02',
    'scope':'Read-only Creator BMC comparison plus current GET-only HERO Redfish recheck. No host keys/reset, OEM commands, media mount, BIOS or fan configuration writes.',
    'creator':{
        'board':'ProArt Z790-CREATOR WIFI','bios':'3002','bmc':'1.3.13','card_hardware':'R1.04',
        'redfish_target_readings':target_values,'pump_reading_rpm':pump['Reading'],
        'bios_attribute_count':len(attributes),'ipmi_attribute_count':len(ipmi),
        'bios_registry_definition_count':len(definitions),
        'processor_records':len(creator('020-processors')['body']['Members']),
        'memory_slot_records':len(creator('021-memory')['body']['Members']),
        'bios_writes_tested':False,'host_reboot_tested':False,
        'sensor_ui_initial_utc':creator('005-sensor-sample')['utc'],
        'sensor_ui_later_utc':creator('029-sensors-later-values')['utc']
    },
    'hero':{
        'board':'ROG MAXIMUS Z790 HERO','bios':'3107 (earlier same-day hardware test)','bmc':'1.3.13',
        'native_web_readable_target_count':8,'native_web_evidence':'../hero_ipmi_r2_live_20261102/live-verification.json',
        'bios_endpoint_http':h_bios['status'],'bios_version_published_in_redfish':h_system['body'].get('BiosVersion'),
        'redfish_target_sensor_records':0,'processor_records':len(h_processors['body']['Members']),
        'memory_slot_records':len(h_memory['body']['Members']),
        'redfish_recheck_utc':h_system['utc'],
        'firmware_auto_dispatch_tested':False,'native_bios_ipmi_menu_integrated':False
    },
    'limitations':[
        'Creator has seven other motherboard fan records disabled. Cable connections were not verified; disabled does not by itself prove missing firmware support.',
        'Creator BIOS configuration reads and published definitions are verified, not write-back or application after reboot.',
        'The ProArt board/version shown by BMC does not prove its SPI image is byte-identical to the provided CAP.',
        'This run does not verify cold-boot auto-initialization on either board.',
        'ASUS compatibility list marks remote forced BIOS update for Creator but not HERO; full feature equivalence is not established.'
    ],
    'official_sources':[
        'https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_EXPANSION_CARD/Compatible_Model_List.pdf',
        'https://dlcdnets.asus.com/pub/ASUS/mb/Add-on_card/IPMI_Expansion_Card_EM_WEB_EN.pdf'
    ],
    'cleanup':{'creator_logout_confirmed':True,'private_browser_exit_code':0,'hero_get_process_exit_code':0}
}
(OUT/'comparison.json').write_text(json.dumps(comparison,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
evidence=[p for p in (OUT/'responses').glob('*.json') if p.name[:3].isdigit() and p.name[:3] not in ['000','001','033','034']]
evidence+=list((OUT/'hero-current').glob('*.json'))+list((OUT/'screens').glob('*.png'))
evidence+=[OUT/'comparison.json',OUT/'Creator-IPMI-属性定义.json']
manifest={p.relative_to(OUT).as_posix():dict(bytes=p.stat().st_size,sha256=sha(p)) for p in evidence}
(OUT/'evidence-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(dict(creator_bios_attributes=373,creator_ipmi_attributes=30,creator_pump_rpm=pump['Reading'],hero_bios_http=h_bios['status'],evidence_files=len(evidence)),ensure_ascii=False))
