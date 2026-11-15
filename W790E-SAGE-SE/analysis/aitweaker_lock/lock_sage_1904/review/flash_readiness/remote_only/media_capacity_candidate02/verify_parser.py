"""Bind CAP02 parser to actual compiled-EFI logs and corruptions."""
from pathlib import Path
import hashlib,json
from decode_capacity_log import parse
HERE=Path(__file__).resolve().parent;rows=[]
for p in (HERE/'review/native_logs').glob('*.txt'):
    data=p.read_bytes()
    if not data:continue
    r=parse(data);rows.append({'name':p.name,'sha256':hashlib.sha256(data).hexdigest(),'rc10_success':r['rc10_success'],'command_count':r['command_count']})
positive=(HERE/'review/native_logs/positive_cached_mismatch.txt').read_bytes()
negative=(HERE/'review/native_logs/no_scsi.txt').read_bytes()
bad={
 'truncated':positive[:-1], 'non_ascii':positive+b'\xff',
 'bad_title':positive.replace(b'MEDIA-CAPACITY-02',b'MEDIA-CAPACITY-XX'),
 'oversize':positive+b' '*32768,
 'duplicate_count':positive.replace(b'RC10_COMMANDS=1',b'RC10_COMMANDS=1\r\nRC10_COMMANDS=1'),
 'command_two':positive.replace(b'RC10_COMMANDS=1',b'RC10_COMMANDS=2'),
 'false_success':negative.replace(b'TEST_STATUS=8000000000000003',b'TEST_STATUS=0000000000000000'),
 'false_valid':negative.replace(b'RC10_VALID=0',b'RC10_VALID=1'),
 'changed_capacity':positive.replace(b'RC10_DATA_HEX=00007FFF00000200',b'RC10_DATA_HEX=00007FFF00000400'),
 'wrong_cdb':positive.replace(b'RC10_CDB=2500',b'RC10_CDB=2A00'),
 'wrong_timeout':positive.replace(b'RC10_TIMEOUT_100NS=0000000001312D00',b'RC10_TIMEOUT_100NS=0000000000000000'),
 'wrong_selector':positive.replace(b'SELECTOR_DP_HEX=0201',b'SELECTOR_DP_HEX=0202'),
 'wrong_target_count':positive.replace(b'TARGET_ID_COUNT=0001',b'TARGET_ID_COUNT=0002'),
 'incomplete_as_command':positive.replace(b'INVENTORY_COMPLETE=1',b'INVENTORY_COMPLETE=0'),
 'guard_corruption':positive.replace(b'RC10_GUARDS_OK=1',b'RC10_GUARDS_OK=0'),
 'host_error':positive.replace(b'RC10_HOST_STATUS=00',b'RC10_HOST_STATUS=01'),
 'unknown_file_write':positive.replace(b'FILE_OPS=0',b'FILE_OPS=1')}
for name,data in bad.items():
    assert data!=positive
    try:parse(data)
    except (ValueError,KeyError):pass
    else:raise AssertionError('accepted '+name)
r={'status':'PASS','native_logs':rows,'rejected_mutations':list(bad),'parser_sha256':hashlib.sha256((HERE/'decode_capacity_log.py').read_bytes()).hexdigest(),'test_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
(HERE/'build/parser_verification.json').write_text(json.dumps(r,indent=2),encoding='utf8');print(json.dumps({'status':'PASS','native_logs':len(rows),'rejected':len(bad)}))
