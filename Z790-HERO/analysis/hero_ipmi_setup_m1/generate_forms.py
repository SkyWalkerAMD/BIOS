"""Emit standard UEFI IFR + en-US strings without a VFR compiler dependency.

Layouts/opcodes are checked against the pinned EDK II headers in source/reference.
The buffer varstore is private. No donor Setup/ServerSetup offset is reused.
"""
from pathlib import Path
import json,struct,uuid
OUT=Path(__file__).resolve().parent
FORM='74390925-3be7-4cd0-b050-7ed881296c11'
CONFIG='c2614243-a877-4acf-a458-ce2904ec3e10'
DRIVER='92386dc9-e835-46cd-bfba-6578c4513413'
STRINGS={
 'LANG':'English', 'TITLE':'HERO IPMI Setup M1',
 'HELP':'IPMI expansion card sensor initialization for ROG MAXIMUS Z790 HERO BIOS 3107.',
 'AUTO':'Auto initialize at boot',
 'AUTO_HELP':'Default: disabled. Save changes to authorize the four tested BMC initialization commands at ReadyToBoot. A USB-loaded driver may miss that event; use Initialize now. A previous failed attempt blocks replay.',
 'SAVE':'Save configuration', 'SAVE_HELP':'Save pending settings. This does not send any IPMI commands.',
 'STATUS':'IPMI status', 'TARGET_LABEL':'Detected target', 'TARGET_VALUE':'Not detected',
 'CONFIG_LABEL':'Saved auto-init', 'CONFIG_VALUE':'Disabled (default)',
 'BMC_LABEL':'BMC identity', 'BMC_VALUE':'Not queried',
 'RESULT_LABEL':'Last operation', 'RESULT_VALUE':'Not run',
 'COUNT_LABEL':'Target sensor records', 'COUNT_VALUE':'Not scanned',
 'LOCK_LABEL':'Attempt protection', 'LOCK_VALUE':'Not checked',
 'REFRESH':'Refresh BMC status',
 'REFRESH_HELP':'Standard reads only. Temporarily enables PCI memory decoding if needed and restores it afterwards. No OEM initialization, fan control, or reset.',
 'INIT_LINK':'Initialize now...', 'INIT_HELP':'Open the confirmation page. Save Auto initialize as enabled first.',
 'CONFIRM_TITLE':'Confirm IPMI initialization',
 'CONFIRM_TEXT':'Run the four tested initialization commands only when VERSION_ERR is asserted. Requires the saved enable setting. One attempt per driver session; a failure is locked across boots.',
 'INIT':'Confirm initialization now', 'INIT_DO_HELP':'Changes BMC sensor initialization state. Does not change fan PWM or update firmware. May take up to 45 seconds of polling delay.',
 'UNLOCK_LINK':'Clear previous attempt lock...', 'UNLOCK_HELP':'Recovery only. Review the saved log first. Save Auto initialize as disabled before clearing. This does not reset the BMC.',
 'UNLOCK_TITLE':'Clear attempt protection',
 'UNLOCK_TEXT':'Review the previous failure log first. Auto initialize must be saved as disabled. Clearing permits a future attempt; it does not undo BMC changes or reset the device.',
 'UNLOCK':'Confirm clear attempt lock', 'UNLOCK_DO_HELP':'Only deletes HeroIpmiAttempt in the private M1 namespace. The per-session attempt limit remains in force.',
 'NOTE':'Fans, network configuration and remote BIOS update are not implemented in M1.',
 'DEFAULT':'Disabled defaults',
}
IDS={name:i+1 for i,name in enumerate(STRINGS)}
def u16(*v):return struct.pack('<'+'H'*len(v),*v)
def op(code,data=b'',scope=False):
    assert len(data)+2<128
    return bytes([code,len(data)+2|(0x80 if scope else 0)])+data
def question(prompt,help,qid,store=0,offset=0,flags=0):return u16(IDS[prompt],IDS[help],qid,store,offset)+bytes([flags])
def text(prompt,value=None):return op(3,u16(IDS[prompt],0,IDS[value] if value else 0))
def action(prompt,help,qid):return op(0x0c,question(prompt,help,qid,flags=4)+u16(0))
def ref(prompt,help,qid,form):return op(0x0f,question(prompt,help,qid)+u16(form))
def package(kind,data):return struct.pack('<I',len(data)+4|(kind<<24))+data
def generate():
    end=op(0x29)
    form=op(0x0e,uuid.UUID(FORM).bytes_le+u16(IDS['TITLE'],IDS['HELP'])+b'\x01'+uuid.UUID('93039971-8545-4b04-b45e-32eb8326040e').bytes_le,True)
    form+=op(0x24,uuid.UUID(CONFIG).bytes_le+u16(1,8)+b'HeroIpmiCfg\0')
    form+=op(0x5c,u16(IDS['DEFAULT'],0))
    form+=op(1,u16(1,IDS['TITLE']),True)
    form+=op(6,question('AUTO','AUTO_HELP',1,1,4)+b'\0',True)
    form+=op(0x5b,u16(0)+bytes([4,0]))+end # BOOLEAN default false
    form+=action('SAVE','SAVE_HELP',2)
    form+=op(2,u16(IDS['STATUS'],0)+b'\0')
    for label,value in [('TARGET_LABEL','TARGET_VALUE'),('CONFIG_LABEL','CONFIG_VALUE'),('BMC_LABEL','BMC_VALUE'),('RESULT_LABEL','RESULT_VALUE'),('COUNT_LABEL','COUNT_VALUE'),('LOCK_LABEL','LOCK_VALUE')]:form+=text(label,value)
    form+=action('REFRESH','REFRESH_HELP',3)
    form+=ref('INIT_LINK','INIT_HELP',101,2)
    form+=ref('UNLOCK_LINK','UNLOCK_HELP',102,3)
    form+=text('NOTE')+end
    form+=op(1,u16(2,IDS['CONFIRM_TITLE']),True)+text('CONFIRM_TEXT')+action('INIT','INIT_DO_HELP',4)+end
    form+=op(1,u16(3,IDS['UNLOCK_TITLE']),True)+text('UNLOCK_TEXT')+action('UNLOCK','UNLOCK_DO_HELP',5)+end+end
    lang=b'en-US\0';header_size=46+len(lang)
    strings=struct.pack('<II',header_size,header_size)+bytes(32)+u16(IDS['LANG'])+lang
    strings+=b''.join(b'\x14'+v.encode('utf-16-le')+b'\0\0' for v in STRINGS.values())+b'\0'
    packages=package(2,form)+package(4,strings)+package(0xdf,b'')
    blob=uuid.UUID(FORM).bytes_le+struct.pack('<I',20+len(packages))+packages
    dp=b'\x01\x04\x14\x00'+uuid.UUID(FORM).bytes_le+b'\x7f\xff\x04\x00'
    hdr='GUID='+uuid.UUID(CONFIG).bytes_le.hex()+'&NAME='+''.join(f'{ord(c):04x}' for c in 'HeroIpmiCfg')+'&PATH='+dp.hex()
    source='/* Generated by generate_forms.py; reviewed against pinned UEFI IFR. */\n'
    source+='\n'.join('#define S_'+name+' '+str(i) for name,i in IDS.items())+'\n'
    for name,data in [('hii_packages',blob),('vendor_path',dp)]:
        source+='static const uint8_t '+name+'[]={\n'+''.join(' '+','.join(f'0x{b:02x}' for b in data[i:i+16])+',\n' for i in range(0,len(data),16))+'};\n'
    source+='static const C16 config_hdr[]=L"'+hdr+'";\n'
    source+='static const C16 full_request[]=L"'+hdr+'&OFFSET=0&WIDTH=8";\n'
    (OUT/'source/forms.h').write_text(source,encoding='utf-8')
    (OUT/'HERO-M1-HII.bin').write_bytes(blob)
    (OUT/'forms.json').write_text(json.dumps(dict(formset=FORM,config_guid=CONFIG,driver_ffs=DRIVER,config_header=hdr,device_path=dp.hex(),string_ids=IDS,strings=STRINGS,form_ids=[1,2,3],varstore_bytes=8,enabled_offset=4),indent=2)+'\n',encoding='utf-8')
    return blob
if __name__=='__main__':print('HII bytes',len(generate()))
