"""Build HERO-specific read-only registry and native AMI layout from checked IFR.
No Creator question IDs or current values are copied. Current values are read
at run time from the target's Setup variable before publication.
"""
from pathlib import Path
import json, hashlib, xml.etree.ElementTree as ET

OUT=Path(__file__).resolve().parent
REG='BiosAttributeRegistryHERO3107.0.8.0'
items=[('BootupNumLockState','Bootup NumLock State',['Off','On']),
       ('WaitForF1IfError',"Wait For F1 If Error",['Disabled','Enabled']),
       ('POSTDelayTime','POST Delay Time',[f'{i} sec' for i in range(11)])]
attrs=[]
for order,(name,label,choices) in enumerate(items):
    attrs.append(dict(AttributeName=name,DisplayName=label,HelpText='Current BIOS value captured by HERO Remote BIOS R8. Read-only in this release.',
        Type='Enumeration',ReadOnly=True,ResetRequired=True,Hidden=False,GrayOut=False,MenuPath='./Boot',DisplayOrder=order,
        Value=[dict(ValueName=v,ValueDisplayName=v) for v in choices]))
registry={'@odata.type':'#AttributeRegistry.v1_2_0.AttributeRegistry','@odata.context':'/redfish/v1/$metadata#AttributeRegistry.AttributeRegistry',
          'Id':REG,'Name':'HERO 3107 BIOS Attribute Registry','Language':'en','RegistryVersion':'0.8.0','OwningEntity':'HERO IPMI adaptation',
          'RegistryEntries':{'Attributes':attrs,'Dependencies':[],'Menus':[]}}
root=ET.Element('SetupData')
platform=ET.SubElement(root,'Platform',Guid='7C6AA223-90C7-48D7-82D8-4845524F5238',Handle='1')
# The stock AMI client initializes AttributeRegistry to {}, so it can render the
# first page before the registry request finishes. Keep that page independent
# of the registry; navigation to Boot then uses the fully loaded definitions.
intro=ET.SubElement(platform,'Page',PageID='HERO_INFO',PageParentID='0',PageFlags='0',PageTitle='HERO Remote BIOS')
ET.SubElement(intro,'Control',Type='Memo',SubTitle='Select Boot in the left menu to view the captured settings.')
ET.SubElement(intro,'Control',Type='Text',DisplayName='Available settings',Text='Bootup NumLock State, Wait For F1 If Error, POST Delay Time')
ET.SubElement(intro,'Control',Type='Text',DisplayName='Publication mode',Text='Read-only snapshot. Remote changes are not applied in this release.')
ET.SubElement(intro,'Control',Type='Text',DisplayName='If Boot is temporarily blank',Text='Return to HERO Remote BIOS, wait a moment, then select Boot again.')
page=ET.SubElement(platform,'Page',PageID='HERO_BOOT',PageParentID='0',PageFlags='0',PageTitle='HERO Boot (read-only snapshot)')
for name,_,_ in items:ET.SubElement(page,'Control',AttributeName=name)
xml=ET.tostring(root,encoding='utf-8',xml_declaration=True)+b'\n'
legacy_root=ET.Element('SetupData')
legacy_platform=ET.SubElement(legacy_root,'Platform',Guid='7C6AA223-90C7-48D7-82D8-4845524F5238',Handle='1')
legacy_platform.append(ET.fromstring(ET.tostring(page)))
legacy_xml=ET.tostring(legacy_root,encoding='utf-8',xml_declaration=True)+b'\n'
raw=json.dumps(registry,separators=(',',':'),ensure_ascii=True).encode()
boundary='HERO_R8_STATIC_46F2C920'
multipart=(f'--{boundary}\r\nContent-Disposition: form-data; name="static_file"; filename="SetupData.xml"\r\nContent-Type: application/xml\r\n\r\n'.encode()+xml+f'\r\n--{boundary}--\r\n'.encode())
(OUT/'reference').mkdir(exist_ok=True)
for name,data in [('registry.json',raw),('SetupData.xml',xml),('layout-multipart.bin',multipart)]:
    (OUT/'reference'/name).write_bytes(data)
def c_array(name,data):
    return f'static const char {name}[]={{'+','.join(str(x) for x in data)+',0};\n'
(OUT/'source/catalog.h').write_text('#define HERO_REGISTRY "'+REG+'"\n'+c_array('hero_registry_json',raw)+c_array('hero_layout_upload',multipart)+c_array('hero_layout_xml',xml)+c_array('hero_legacy_layout_xml',legacy_xml))
(OUT/'reference/catalog.json').write_text(json.dumps({'registry':REG,'read_only':True,'attributes':3,'bios':'3107',
    'files':{name:hashlib.sha256(data).hexdigest() for name,data in [('registry.json',raw),('SetupData.xml',xml),('layout-multipart.bin',multipart)]}},indent=2)+'\n')
print(json.dumps({'registry_bytes':len(raw),'xml_bytes':len(xml),'multipart_bytes':len(multipart),'read_only':True}))
