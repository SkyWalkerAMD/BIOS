"""Reject incomplete/contradictory descriptor exports; synthetic logs only."""
from pathlib import Path
import hashlib,importlib.util,json
HERE=Path(__file__).resolve().parent
parser=HERE.parents[3]/'remote_172_20_2_162/read_spi_descriptor02_qr.py'
spec=importlib.util.spec_from_file_location('fd02_decoder',parser)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
positive=(HERE/'frontend_logs/captured_busy_FGO_native_CPU_IO2.txt').read_bytes()
blob,meta=m.parse_descriptor(positive)
assert len(blob)==4096 and meta['status']=='DESCRIPTOR_4K_CAPTURED_TWO_PASSES_MATCH'
cases=[{'name':'complete_two_pass_descriptor_with_busy_observation','passed':True}]
negative=(HERE/'frontend_logs/native_busy_FGO_error_refused.txt').read_bytes()
assert m.parse_descriptor(negative)[0] is None
cases.append({'name':'failed_read_exports_no_descriptor','passed':True})
for name,old,new in [
    ('wrong_block_count',b'COMPLETED_BLOCKS=0x00000080',b'COMPLETED_BLOCKS=0x0000007F'),
    ('wrong_row_offset',b'0000:',b'0001:'),
    ('failed_protection_readback',b'PROTECTION_SNAPSHOT_UNCHANGED=0x1',b'PROTECTION_SNAPSHOT_UNCHANGED=0x0'),
    ('missing_end',b'PROBE_COMPLETE\r\n',b''),
    ('failure_cannot_export',b'CAPTURE_STATUS=0x0000000000000000',b'CAPTURE_STATUS=0x8000000000000007'),
    ('impossible_poll_count',b'POLL_OBSERVATIONS=0x00000100',b'POLL_OBSERVATIONS=0x0000007F'),
    ('busy_count_cannot_equal_total',b'EXACT_BUSY_FGO_OBSERVATIONS=0x00000080',b'EXACT_BUSY_FGO_OBSERVATIONS=0x00000100'),
]:
    assert positive.count(old)==1,(name,old)
    try:m.parse_descriptor(positive.replace(old,new))
    except ValueError:pass
    else:raise AssertionError(name)
    cases.append({'name':name,'passed':True})
out={'status':'PASS','cases':cases,'parser_sha256':sha(parser),'verification_source_sha256':sha(Path(__file__)),
     'input_log_sha256':hashlib.sha256(positive).hexdigest(),'synthetic_only':True}
(HERE/'parser_regression.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':'PASS','cases':len(cases),'parser_sha256':sha(parser)}))
