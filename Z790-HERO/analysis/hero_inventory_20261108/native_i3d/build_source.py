"""Derive I3d helpers from frozen I3b without modifying the prior live package."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
old = BASE / 'native/inventory_legacy71.c'
assert hashlib.sha256(old.read_bytes()).hexdigest() == '41af4c7705a99cdb9b59f3f6bc193bfa0f5eca0603d22b3cda1a68121aa6065c'
source = old.read_text('utf8').split('static ES verify_item(')[0]
source = source.replace('static JSON actual,expected,baseline;', 'static JSON actual,expected;')
source = source.replace('static char baseline_body[32769],fresh_etag[256];\nstatic UN baseline_bytes;', 'static char fresh_etag[256];')
source = source.replace('static unsigned stage,done_mask,attempted_mask;', 'static unsigned stage,done_mask,attempted_mask,indexed_mask,summary_attempted,summary_verified;')
start = source.index('static int baseline_unchanged(void)')
end = source.index('static int source_valid(void)', start)
source = source[:start] + source[end:]
source = source.replace('I3B_', 'I3D_')
source = source.replace('return self==512||jeq(&actual,self,paths[id]);',
                        'return ((id<7||id>11)&&self==512)||jeq(&actual,self,paths[id]);')
source = source.replace('/* .71-only first live publisher.', '/* .71-only I3d continuation publisher; frozen I3b remains unchanged.')
(HERE / 'inventory_legacy71.c').write_text(source + (HERE / 'continuation_tail.c.in').read_text('utf8'), encoding='utf8', newline='\n')
adapter = (BASE / 'native/test_legacy71_adapter.c').read_text('utf8')
adapter = adapter.replace('stage=0;done_mask=0;attempted_mask=0;source_epoch=0;baseline_bytes=0;',
                          'stage=0;done_mask=0;attempted_mask=0;source_epoch=0;indexed_mask=0;summary_attempted=0;summary_verified=0;')
(HERE / 'test_legacy71_adapter.c').write_text(adapter, encoding='utf8', newline='\n')
summary = {'ProcessorSummary': {'Count': 1, 'Model': 'Intel(R) Core(TM) i9-14900KS'}}
(HERE / 'processor-summary.patch.json').write_bytes(json.dumps(summary, separators=(',', ':')).encode('ascii'))
print('Generated independent I3d source and test adapter; I3b unchanged.')
