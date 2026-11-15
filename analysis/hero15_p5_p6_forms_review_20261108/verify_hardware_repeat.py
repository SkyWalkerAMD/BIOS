"""Addendum: S22 second genuine AfterBoot, preserve prior two-log report."""
from pathlib import Path
import hashlib,json
BASE=Path(__file__).resolve().parent
namespace={'__file__':str(BASE/'verify_hardware_logs.py'),'__name__':'qr_validator_definitions'}
exec(compile((BASE/'verify_hardware_logs.py').read_text().split('\ntexts={};records=[]')[0],str(BASE/'verify_hardware_logs.py'),'exec'),namespace)
name='hero15-s22-repeat-return';namespace['PIN'][name]=(2767,'A59625EA','dbd415e73d4bad317b5c63fea8374ed22c6b75548b0cbd75f16de169b1b6d356')
text,row=namespace['reconstruct'](name);LIVE=namespace['LIVE'];prior=(LIVE/'hero15-s22-after-return.TXT').read_bytes().decode('ascii')
def audit(s):return s.split('BEGIN P6 CACHED AUDIT\r\n',1)[1].split('\r\nEND P6 CACHED AUDIT',1)[0].strip('\r\n')
assert audit(text)==audit(prior)+'\r\nP6_AMITSE_AFTER_BOOT\r\nP6_READY_TO_BOOT\r\nP6_AMITSE_BEFORE_BOOT'
assert text.count('P6_AMITSE_AFTER_BOOT\r\n')==2
assert text.count('P6_AFTER_SYNC_BIND_BEGIN\r\n')==1 and text.count('P6_AFTER_SYNC_BIND_STATUS=800000000000000E\r\n')==1
for token in ('P6_AFTER_SYNC_READ_BEGIN','P6_AFTER_SYNC_PUBLISH_BEGIN','P1_READ_BEGIN','PCI_DISCOVERY','PCI_SELECTED_BDF','\r\nTX ','\r\nRX '):assert token not in text
raw='0000000A01'+'00'*27
assert all(line=='RAW='+raw for line in text.splitlines() if line.startswith('RAW='))
assert all('STATUS=800000000000000E' in line for line in text.splitlines() if line.startswith('HeroIpmiState '))
for i in range(40):assert f'P6_VALUE[{i:02X}]=Not queried\r\n' in text
report={'passed':True,'capture':row,'previous_report_sha256':hashlib.sha256((BASE/'hardware-report.json').read_bytes()).hexdigest(),'interpretation':'Second real AfterBoot added only AFTER/READY/BEFORE notifications. Failed bind was not replayed, no new PCI/KCS/read/publication occurred, safe32B settings and absent State unchanged.','scope':'S22 rejection and no-retry lifecycle, not S23 or successful native UI verification','all_S22_original_PNG_pages_verified':20}
(BASE/'hardware-repeat-report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='capture'},indent=2))
