"""Retarget independent existing tests without changing their baseline files."""
from pathlib import Path
HERE=Path(__file__).resolve().parent;EBS=HERE.parent/'ebs_candidate'
s=(EBS/'run_full_regression.py').read_text(encoding='utf8')
s=s.replace("del sources['driver/services.c']\nsources['review/flash_readiness/ebs_candidate/services.c'] = candidate['candidate_source_sha256']", "for name, digest in candidate['candidate_sources'].items():\n    del sources['driver/'+name]\n    sources['review/flash_readiness/late_attach_candidate/'+name] = digest")
s=s.replace("if x=='services'", "if x in ['platform','hii','ui','services']")
needle="    if name == 'verify_history.py':"
assert needle in s
s=s.replace(needle,"""    if name == 'verify_hii_abi.py':
        # The ABI suite tests valid managed callbacks. Seed its newly explicit
        # ownership precondition; negative ownership has a separate new suite.
        marker = \"    u.mem_write(symbols['original_callback'],q(STOP+0x100))\"
        assert marker in source
        source = source.replace(marker, marker + \"\\n    u.mem_write(symbols['loop_depth'],struct.pack('<I',1))\\n    u.mem_write(symbols['password_core']+200,b'\\\\1')\")
"""+needle)
s=s.replace("'The EBS-specific 83 cases and OVMF handoff tests remain separately reported, not counted again here.'", "'EBS and late-attach ownership cases are separately reported, not counted again here.', 'HII ABI fixture seeds an owned active session to match the new explicit precondition; all original ABI assertions remain intact.'")
(HERE/'run_full_regression.py').write_text(s,encoding='utf8')
# The EBS test body executes the new complete EFI, preserving all 83 assertions.
(HERE/'verify_ebs.py').write_text((EBS/'verify_candidate.py').read_text(encoding='utf8').replace('candidate_regression.json','ebs_regression.json'),encoding='utf8')
print('Retargeted six suites and existing EBS suite; original files unchanged.')
