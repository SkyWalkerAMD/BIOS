"""A separate HERO IPMI formset, using the donor's menu class, not donor code."""
from pathlib import Path
import struct,uuid,json
OUT=Path(__file__).resolve().parent
FORM='491ef9f7-625c-48dc-b140-2c8577ba47f1'
values=['RESULT','SELFTEST','DEVICE','REVISION','FIRMWARE','IPMI','MFG','PRODUCT',
 'WDT_RUNNING','WDT_USE','WDT_POLICY','WDT_INITIAL','WDT_REMAINING',
 'SEL_COUNT','SEL_FREE','SEL_OVERFLOW','SEL_LOGGING','SEL_RANGE',
 'CHANNEL','SOURCE','IP','MASK','GATEWAY','MAC']+['SEL'+str(i) for i in range(16)]
labels=['Last refresh','BMC Self Test Status','BMC Device ID','BMC Device Revision',
 'BMC Firmware Revision','IPMI Version','Manufacturer ID','Product ID',
 'Timer state','Timer owner','Timeout policy','Initial countdown (100 ms units)','Remaining countdown (100 ms units)',
 'SEL entries','SEL free bytes','SEL overflow','System event logging','Displayed records',
 'LAN channel','IP address source','Station IP address','Subnet mask','Gateway IP address','MAC address']+['Record '+str(i+1) for i in range(16)]
strings={'LANG':'English','TITLE':'IPMI','HELP':'ASUS IPMI expansion card on ROG MAXIMUS Z790 HERO.',
 'REFRESH':'Refresh BMC information','REFRESH_HELP':'Read identity, self-test, watchdog, LAN and the first 16 event records. Optional unsupported commands remain unavailable.',
 'NETWORK':'BMC network configuration','NETWORK_HELP':'Current LAN settings read from the BMC. Editing has not been enabled in this P1 build.',
 'WATCHDOG':'OS Watchdog Timer','WATCHDOG_HELP':'Actual BMC watchdog state. This build neither starts nor reconfigures the timer.',
 'EVENT':'System Event Log','EVENT_HELP':'BMC event log status.',
 'VIEW':'View System Event Log','VIEW_HELP':'Lossless raw records, with standard/OEM type distinguished. P1 does not clear the SEL.',
 'NOTE':'P1: information and event viewing. Configuration writes are not enabled.',
 'LED':'MLED / BMC_LED synchronization: pending callback adaptation.',
 'INBAND':'In-Band driver type: pending ACPI / firmware adaptation.'}
for name,label in zip(values,labels):strings['L_'+name]=label;strings['V_'+name]='Not queried'
ids={k:i+1 for i,k in enumerate(strings)}
def h(*v):return struct.pack('<'+'H'*len(v),*v)
def op(c,p=b'',s=False):return bytes([c,(len(p)+2)|(128 if s else 0)])+p
def pack(t,p):return struct.pack('<I',len(p)+4|(t<<24))+p
def text(name):return op(3,h(ids['L_'+name],0,ids['V_'+name]))
def static(name):return op(3,h(ids[name],0,0))
def question(name,qid):return h(ids[name],ids.get(name+'_HELP',0),qid,0,0)+b'\0'
def ref(name,qid,form):return op(0xf,question(name,qid)+h(form))
def generate():
 end=op(0x29)
 f=op(0xe,uuid.UUID(FORM).bytes_le+h(ids['TITLE'],ids['HELP'])+b'\1'+uuid.UUID('93039971-8545-4b04-b45e-32eb8326040e').bytes_le,True)
 # Exact class/subclass structure from the Creator ServerMgmtSetup formset.
 tiano=uuid.UUID('0f0b1735-87a0-4193-b266-538c38af48ce').bytes_le
 f+=op(0x5f,tiano+b'\3'+h(0x14))+op(0x5f,tiano+b'\4'+h(0))
 f+=op(1,h(8001,ids['TITLE']),True)
 for name in values[1:8]:f+=text(name)
 f+=ref('WATCHDOG',101,8002)+static('LED')+static('INBAND')
 f+=ref('EVENT',102,8004)+ref('NETWORK',103,8024)+ref('VIEW',104,8027)
 f+=op(0xc,h(ids['REFRESH'],ids['REFRESH_HELP'],1,0,0)+b'\4'+h(0))
 f+=text('RESULT')+static('NOTE')+end
 for form,name,rows in [(8002,'WATCHDOG',values[8:13]),(8004,'EVENT',values[13:18]),(8024,'NETWORK',values[18:24]),(8027,'VIEW',values[24:])]:
  f+=op(1,h(form,ids[name]),True)
  for row in rows:f+=text(row)
  f+=end
 f+=end
 language=b'en-US\0';header=46+len(language)
 s=struct.pack('<II',header,header)+bytes(32)+h(ids['LANG'])+language
 s+=b''.join(b'\x14'+v.encode('utf-16-le')+b'\0\0' for v in strings.values())+b'\0'
 packages=pack(2,f)+pack(4,s)+pack(0xdf,b'')
 blob=uuid.UUID(FORM).bytes_le+struct.pack('<I',20+len(packages))+packages
 dp=b'\1\4\x14\0'+uuid.UUID(FORM).bytes_le+b'\x7f\xff\4\0'
 source='/* Generated. Independent formset, no donor varstore. */\n'
 for name,data in [('hii_packages',blob),('vendor_path',dp)]:
  source+='static const uint8_t '+name+'[]={\n'+''.join(' '+','.join(f'0x{x:02x}' for x in data[i:i+16])+',\n' for i in range(0,len(data),16))+'};\n'
 source+='static const uint16_t value_ids[]={'+','.join(str(ids['V_'+k]) for k in values)+'};\n'
 (OUT/'source/forms.h').write_text(source)
 (OUT/'HERO-P1-HII.bin').write_bytes(blob)
 (OUT/'forms.json').write_text(json.dumps(dict(formset=FORM,class_id=20,subclass=0,strings=strings,ids=ids,values=values,forms=[8001,8002,8004,8024,8027]),indent=2)+'\n')
 return blob
if __name__=='__main__':print('HII bytes',len(generate()))
