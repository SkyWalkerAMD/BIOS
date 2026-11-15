"""Prepare I2 in a new child directory; never overwrite I1 sources or media."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;I1=HERE.parent;OUT=HERE/'i2-build';ROOT=I1.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 OUT.mkdir(exist_ok=True);copied=[]
 for name in ['efi_min.h','collector.h','common.c','kvm.h','kvm.c','compat/assert.h','compat/stdlib.h','compat/string.h','vendor/qrcodegen.c','vendor/qrcodegen.h']:
  src=I1/'source'/name;dest=OUT/'source'/name;dest.parent.mkdir(parents=True,exist_ok=True)
  text=src.read_text()
  if name in ['collector.h','kvm.c']:text=text.replace('786432','147456')
  if name=='kvm.c':
   text=text.replace('HERO-SMBIOS-I1','HERO-FW-ID-I2').replace('HERO SMBIOS I1','HERO FW ID I2')
   text=text.replace('text_starts[131073]','text_starts[32769]').replace('text_count<131072','text_count<32768')
  dest.write_text(text,encoding='ascii',newline='\n')
  copied.append({'source':str(src.relative_to(ROOT)),'source_sha256':sha(src),'target':str(dest.relative_to(OUT)),'target_sha256':sha(dest)})
 for name in ['firmware_probe.c','firmware_probe.h']:
  (OUT/'source'/name).write_bytes((HERE/name).read_bytes())
  copied.append({'source':str((HERE/name).relative_to(ROOT)),'source_sha256':sha(HERE/name),'target':'source/'+name,'target_sha256':sha(HERE/name)})
 script=(I1/'build.py').read_text().replace('ROOT=P.parents[1]','ROOT=P.parents[3]')
 script=script.replace("'smbios'","'firmware_probe'").replace("'/export:smbios_entry','/export:smbios_table'","'/export:firmware_probe','/export:fp_path_targets','/export:fp_range_readable'")
 script=script.replace('SMBIOS capture','firmware identity capture').replace('HERO-SMBIOS-I1','HERO-FW-ID-I2')
 script=script.replace('HERO_SMBIOS_I1','HERO_FW_ID_I2').replace('HERO_INV.TAG','HERO_ID.TAG').replace('SMBIOS I1','FW ID I2')
 (OUT/'build.py').write_text(script,encoding='ascii',newline='\n')
 decode=(I1/'decode_captures.py').read_text().replace('ROOT=OUT.parents[1]','ROOT=OUT.parents[3]')
 decode=decode.replace('HERO-SMBIOS-I1','HERO-FW-ID-I2').replace('SMBIOS I1','FW ID I2').replace('END SMBIOS SNAPSHOT','END FW ID SNAPSHOT').replace('786432','147456')
 (OUT/'decode_captures.py').write_text(decode,encoding='ascii',newline='\n')
 launch=(I1/'source/launcher.c').read_text()
 launch=launch.replace('/* Read-only SMBIOS inventory. Only explicit L writes a new marked-USB file.','/* Read-only firmware identity. Only explicit L writes a new marked-USB file.')
 launch=launch.replace('#include "kvm.h"','#include "kvm.h"\n#include "firmware_probe.h"')
 lines=launch.splitlines(True)
 lines=[x for x in lines if not any(x.startswith(p) for p in ['static GUID sm3=','static GUID sm2=','static uint8_t raw[','static SM_ENTRY ','static SM_TABLE '])]
 launch=''.join(lines).replace('static unsigned snapshot_bad,captured,valid,entry3_len,entry2_len;','static unsigned snapshot_bad,captured,valid;')
 start=launch.index('static void bytes(');end=launch.index('static ES mount_log_volume(',start)
 launch=launch[:start]+'''static void identity_append(void *ctx,const char *bytes,size_t length){(void)ctx;add_n(bytes,length);}
static ES collect(void){
 snapshot_len=0;snapshot_bad=0;valid=0;captured=1;
 add("HERO-FW-ID-I2\\r\\nRUN=");add(run_id);add("\\r\\n");
 add("READ_ONLY firmware identity; no BMC, PCI, NV or initialization.\\r\\n");
 ES e=firmware_probe(gST,identity_append,0);valid=!FAILED(e);
 field("FP_PROBE_RETURN",e,16);field("CAPTURE_COMPLETE",valid,2);
 add("END FW ID SNAPSHOT\\r\\n");return snapshot_bad?ERR(5):e;
}
'''+launch[end:]
 launch=launch.replace('HERO-SMBIOS-I1','HERO-FW-ID-I2').replace('HERO SMBIOS I1','HERO FW ID I2').replace('HERO_INV.TAG','HERO_ID.TAG').replace('INV000.TXT','FID000.TXT')
 launch=launch.replace('WAITING FOR S','WAITING FOR F').replace('Inventory capture only. S starts','Read firmware identity only. F starts')
 launch=launch.replace('S=capture SMBIOS.','F=capture firmware identity.').replace("if(k=='S')","if(k=='F')")
 launch=launch.replace('SMBIOS_READ_BEGIN','FIRMWARE_ID_READ_BEGIN').replace('SMBIOS capture status:','Firmware identity status:')
 launch=launch.replace('   status("Raw table bytes: ",valid?metadata.used:0);status("Export bytes: ",snapshot_len);','   status("Export bytes: ",snapshot_len);')
 launch=launch.replace('SMBIOS_CAPTURE_READY','FIRMWARE_ID_CAPTURE_READY').replace('SMBIOS_CAPTURE_INCOMPLETE','FIRMWARE_ID_CAPTURE_INCOMPLETE').replace('Use S, C, R, L, or Q.','Use F, C, R, L, or Q.')
 (OUT/'source/launcher.c').write_text(launch,encoding='ascii',newline='\n')
 (OUT/'source-provenance.json').write_text(json.dumps(copied,indent=2)+'\n')
 print('Prepared I2 only in '+str(OUT))
if __name__=='__main__':main()
