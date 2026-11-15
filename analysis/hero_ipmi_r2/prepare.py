"""Create R2 source from recorded, unchanged M1/M1f baselines."""
from pathlib import Path
import hashlib,json,shutil
OUT=Path(__file__).resolve().parent; ROOT=OUT.parents[1]
SRC=OUT/'source'; SRC.mkdir(exist_ok=True)
old=ROOT/'analysis/hero_ipmi_setup_m1/source'
display=ROOT/'analysis/hero_display_m1f/source'
provenance={}
def cp(source,dest):
    data=source.read_bytes(); dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(data)
    provenance[str(dest.relative_to(OUT))]={'source':str(source.relative_to(ROOT)),'sha256':hashlib.sha256(data).hexdigest()}
for n in ('common.c','engine.c','probe_core.c','probe_core.h'):
    cp(old/n,SRC/n)
    if n.endswith('.c'):
        p=SRC/n;p.write_text(p.read_text().replace('"m1.h"','"r2.h"'),encoding='utf-8')
cp(display/'efi_min.h',SRC/'efi_min.h')
for n in ('kvm.c','kvm.h','compat/string.h','compat/stdlib.h','compat/assert.h','vendor/qrcodegen.c','vendor/qrcodegen.h'):
    if (display/n).exists():cp(display/n,SRC/n)
p=SRC/'kvm.c';s=p.read_text()
s=s.replace('HERO-M1F-QR1','HERO-IPMI-R2-QR1').replace('HERO HII M1F - KVM LOG','HERO IPMI R2 - KVM LOG').replace('HERO HII M1f KVM - diagnostic only','HERO IPMI R2 KVM - log capture').replace('M1f log viewer closed','R2 log viewer closed')
s=s.replace('65537','131073').replace('65536','131072')
p.write_text(s,encoding='utf-8')
p=SRC/'common.c';s=p.read_text().replace('GUID config_guid=CFG_GUID_INIT,form_guid=FORM_GUID_INIT,api_guid=API_GUID_INIT;','GUID config_guid=CFG_GUID_INIT,api_guid=API_GUID_INIT;\nuint32_t config_source;')
s=s.replace('*c=(CONFIG){CFG_MAGIC,0,1,{0,0}};','*c=(CONFIG){CFG_MAGIC,1,1,{0,0}}; config_source=2;')
s=s.replace('if(e==ERR(14))return 0; /* Missing is disabled, and is NOT written at boot. */','if(e==ERR(14)){config_source=0;return 0;} /* R2 firmware default enabled; no implicit NVRAM write. */')
s=s.replace('*c=v;return 0;','*c=v;config_source=1;return 0;')
s=s.replace('if(!FAILED(e) && eq(&old,c,sizeof(old)))return 0;','if(!FAILED(e) && config_source==1 && eq(&old,c,sizeof(old)))return 0;')
s=s.replace('return FAILED(e)?e:eq(&old,c,sizeof(old))?0:ERR(7);','return FAILED(e)?e:config_source==1 && eq(&old,c,sizeof(old))?0:ERR(7);')
p.write_text(s,encoding='utf-8')
p=SRC/'engine.c';s=p.read_text().replace('M1:', 'R2:').replace('saved opt-in','enabled configuration').replace('M1_', 'R2_')
s=s.replace('Initialization disabled. Enable and save Auto initialize first.','Initialization disabled. Save enabled configuration first.')
s=s.replace('    return 1;\n}\nstatic int snapshot(void)', '''    if(id==0xfb || seen[id]==2){
        logtext("SENSOR id=");loghex(id,2);logtext(" type=");loghex(type,2);
        logtext(" event=");loghex(event,2);logtext(" raw=");loghex(rx[3],2);
        logtext(" flags=");loghex(rx[4],2);logtext("\\r\\n");
    }
    return 1;
}
static int snapshot(void)''')
s=s.replace('    size_t n;uint8_t repo[272];size_t repo_n;','    logtext("SDR_SNAPSHOT_BEGIN\\r\\n");\n    size_t n;uint8_t repo[272];size_t repo_n;')
s=s.replace('                report.targets++;','                report.targets++;seen[sensor.number]=2;')
s=s.replace('    return 1;\n}\nES EA engine_run','    logtext("SDR_SNAPSHOT_END targets=");loghex(report.targets,2);logtext(" readable=");loghex(report.readable,2);logtext(" version_asserted=");loghex(report.version_asserted,2);logtext("\\r\\n");\n    return 1;\n}\nES EA engine_run')
s=s.replace('    report.identity=1;','    report.identity=1;logtext("BMC_ID ");logbytes(rx,n);')
p.write_text(s,encoding='utf-8')
cp(ROOT/'analysis/hero_display_m1f/decode_captures.py',OUT/'decode_captures.py')
p=OUT/'decode_captures.py';s=p.read_text().replace('HERO-M1F-QR1','HERO-IPMI-R2-QR1').replace('65536','131072').replace('M1f','R2').replace('M1F','R2');p.write_text(s,encoding='utf-8')
(OUT/'baseline-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
print('R2 baseline prepared; old files preserved.')
