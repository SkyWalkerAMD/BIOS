"""Preserve the local protocol findings with immutable source digests."""
from pathlib import Path
import hashlib
import json

base = Path(__file__).resolve().parent
root = base.parents[1]
live = root / 'analysis/hero_ipmi_continued_live_20261108'
paths = [
    live / 'hero71-i3b-system-cpu.TXT',
    live / 'responses/697-get.json', live / 'responses/701-get.json',
    live / 'responses/702-get.json', live / 'responses/967-evaluate.json',
    base / 'rea-cpu-index/responses/002-cpu-post-completion.json',
    base / 'rea-legacy/responses/002-legacy-0x1f7c.c',
    base / 'rea-legacy/responses/003-resource-writes-0xf554.c',
]
record = {
    'status': 'CPU object and vendor UI/API verified; standard collection index incomplete',
    'writes_performed_by_this_agent': False,
    'observed_live_facts_from_parent_evidence': [
        'System PATCH returned HTTP204 and direct readback has the exact HERO own identity.',
        'CPU POST returned HTTP201 and Location identifies DevType1_CPU0.',
        'Three subsequent internal Processors collection GETs and external 701 GET show Members=[] and count0.',
        'External 702 direct CPU GET200 contains the expected Intel14900KS model and24/24/32 counts.',
        'Vendor host_interface_processor_info GET200 in967 returns the same CPU for the web UI.',
        'Vendor host_interface_system_info GET200 in967 returns correct HERO model/version/UUID.',
    ],
    'shipped_artifact_facts': {
        'publisher_sha256': 'e1fd4b36c4bf60386b06d1b8fbe8c323735f1c1c110c2cb6ac0bf6e75df7d4b4',
        'rea_evidence': 'ev_5219643194bf39e4d83603cc3e87cdc378603aea5580afdb1e3116697e2d927b',
        '0xd3d0': 'Builds System.ProcessorSummary Count, Model and Status; no Members field.',
        '0xf554': 'After successful CPU child publishing, calls0xd3d0 on pending System JSON.',
        '0x1f7c': 'Legacy routine finally PATCHes pending System and Chassis JSON.',
        '0x19384': 'POST helper sends Content-Type/Length/OData-Version and extracts Location; no further commit here.',
        '0x488': 'Legacy path clears/updates group CRC around0x1f7c; bulk path is separate.',
        '0x312c': 'Legacy group CRC metadata POST; not a documented membership repair.',
    },
    'limits': [
        'No proof that ProcessorSummary PATCH rebuilds standard collection membership.',
        'No proven safe legacy collection repair request; do not invent Members PATCH or BootComplete.',
        'Do not repeat CPU POST: object already exists and is visible through the actual vendor UI API.',
        'No automatic bulk fallback; I3c draft remains paused and untested.',
        'Cross-boot and BMC-reboot persistence have not been established by this evidence.',
    ],
    'next_module': 'native_i3d/handoff.json',
    'source_files': [
        {'path': str(p.relative_to(root)), 'bytes': p.stat().st_size,
         'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths
    ],
}
(base / 'cpu-index-findings.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf8')
print('Saved bounded CPU collection findings and source digests.')
