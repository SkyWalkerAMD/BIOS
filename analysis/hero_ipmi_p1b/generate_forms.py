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
 end=op(0x29);f=b''
 strings['HELP']='BMC information snapshot captured by HERO P1b. Settings are read-only in this build.'
 strings['NOTE']='Snapshot only. Reopen the P1b tool to refresh BMC data.'
 for form,name,rows in [(0xe100,'TITLE',values[1:8]),(0xe101,'WATCHDOG',values[8:13]),(0xe102,'EVENT',values[13:18]),(0xe103,'NETWORK',values[18:24]),(0xe104,'VIEW',values[24:])]:
  f+=op(1,h(form,ids[name]),True)
  for row in rows:f+=text(row)
  if form==0xe100:
   f+=ref('WATCHDOG',0xe111,0xe101)+ref('EVENT',0xe112,0xe102)+ref('NETWORK',0xe113,0xe103)+ref('VIEW',0xe114,0xe104)
   f+=static('LED')+static('INBAND')+static('NOTE')
  f+=end
 offsets=[];p=0
 while p<len(f):
  c=f[p];n=f[p+1]&127
  for off in ({1:[4],3:[2,4,6],0xf:[2,4]}.get(c,[])):
   if int.from_bytes(f[p+off:p+off+2],'little'):offsets.append(p+off)
  p+=n
 source='/* Generated read-only pages appended inside the verified HERO formset. */\n'
 source+='static const char *const native_strings[]={\n'+',\n'.join(json.dumps(v) for v in strings.values())+'};\n'
 source+='static const uint8_t native_form_template[]={'+','.join(str(x) for x in f)+'};\n'
 source+='static const uint16_t native_string_offsets[]={'+','.join(str(x) for x in offsets)+'};\n'
 source+='static const uint16_t native_value_ids[]={'+','.join(str(ids['V_'+x]) for x in values)+'};\n'
 source+='#define NATIVE_TITLE '+str(ids['TITLE'])+'\n#define NATIVE_HELP '+str(ids['HELP'])+'\n'
 (OUT/'source/native_forms.h').write_text(source)
 (OUT/'HERO-P1b-native-forms.bin').write_bytes(f)
 (OUT/'forms.json').write_text(json.dumps(dict(formset='7b59104a-c00d-4158-87ff-f04d6396a915',advanced_form=10005,forms=[0xe100,0xe101,0xe102,0xe103,0xe104],strings=strings,string_patch_offsets=offsets,values=values,all_read_only=True),indent=2)+'\n')
 return f
if __name__=='__main__':print('Native IFR bytes',len(generate()))
