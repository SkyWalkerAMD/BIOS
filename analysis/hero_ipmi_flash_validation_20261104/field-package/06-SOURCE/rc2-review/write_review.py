"""Index actual REA records and scoped findings without treating static work as execution."""
from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent
ROOT=P.parents[1]
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    entries=[]
    for session in ('driver-loopback','driver-seeded','dxe','amitse'):
        for path in sorted((P/session/'responses').glob('*.json')):
            response=json.loads(path.read_text())['result']
            assert not response.get('isError',False),path
            d=response.get('structuredContent',{})
            if 'evidence_id' not in d: continue
            n=d.get('normalized_result')
            entry=dict(session=session,response=path.relative_to(P).as_posix(),
                response_sha256=sha(path),evidence_id=d['evidence_id'],operation=d['operation'],
                target=d.get('subject'),provider=d.get('provider'),parameters=d.get('parameters'),
                limitations=d.get('limitations'),analysis_profile=d.get('analysis_profile'))
            if isinstance(n,dict) and 'items' in n:
                entry['items']=[dict(address=x.get('address'),status=x.get('status'),
                    pseudocode_present=isinstance(x.get('pseudocode'),str)) for x in n['items']]
            entries.append(entry)
        assert (P/session/'evidence.json').is_file()
    skill=ROOT/'tools/rea-runtime/node_modules/rea-agents/skills/reverse-engineer-anything/SKILL.md'
    report=dict(date='2026-11-03',rea_version='6.8.0',ghidra_version='12.1.4',
        skill=dict(name='reverse-engineer-anything',version='49',path=str(skill),sha256=sha(skill)),
        candidate_sha256='5906d1bca3dbaa1157ecf36ecff1a1123bfe4b6fb896aeb33d354ab4ef21b521',
        hardware_flashed_this_review=False,bmc_accessed_this_review=False,
        observations=[
            dict(id='C1',status='corrected',finding='RC1 driver was in outer FV; RC2 places the byte-identical driver in the existing inner DXE FV.',evidence=['rc2-container-review.json','rc2/build.json']),
            dict(id='C2',status='passed_static',finding='Independent direct parsing and UEFIExtract: 714 existing FFS unchanged, three changed containers/resources, one added driver; Setup, SPF and runtime match reviewed inputs.',evidence=['rc2-container-review.json']),
            dict(id='C3',status='observed_static',finding='Original DXE entry stub 0xbf0 calls 0xe2c, which calls 0xc20. 0xc20 registers the LZMA GUID and handler pointers; 0xe2c publishes registered GUID section interfaces before later dispatch.',evidence=['dxe-entry-stub.json','dxe/responses/005-lzma-constructor.json','dxe/responses/007-core-entry.json']),
            dict(id='C4',status='observed_static',finding='Original HERO AMITSE constructs SetupEnter GUID on stack and invokes helper 0x176c to install and immediately uninstall the marker. Early RegisterProtocolNotify has a corresponding publisher; LocateProtocol after the signal cannot replay it.',evidence=['amitse/responses/005-setupenter-signal.json','setupenter-guid-findings.json']),
            dict(id='C5',status='observed_static',finding='Compiled driver arms a TPL_CALLBACK timer, attempts exact resource binding at most 20 times, queries once after matching, and closes its events before unload.',evidence=['driver-loopback/responses/002-entry.json','driver-loopback/responses/003-core.json','driver-seeded/responses/002-timer.json','driver-seeded/responses/003-unload.json']),
            dict(id='C6',status='passed_scoped',finding='Compiled publisher checks exact IFR and all 40 value IDs in ten languages, limits writes to those IDs and reads all results back. Compiled transport retains board/BIOS/card/BMC guards, read command whitelist, finite polling budgets and PCI restore.',evidence=['driver-loopback/responses/003-core.json','prior-P5-tests-and-preflight']),
            dict(id='C7',status='observed_static_partial',finding='AMITSE preferred 0xb1684 and fallback 0x4879c string paths call HII String GetString. This does not establish when an existing GUI widget reads a changed string again.',evidence=['amitse/responses/002-string-lookup.json','amitse/responses/003-text-controls.json','amitse/responses/008-preferred-string-path.json']),
            dict(id='C8',status='passed_static',finding='Independent IFR/SPF checks found five consistent pages and 48 controls. Original executable sections and 1801 DIR64 relocation entries remain unchanged; no relocations target moved resource/relocation ranges.',evidence=['menu-review.json','menu-spf-independent.json','menu-pe-independent.json'])],
        unresolved=[
            'Whether FlashBack accepts RC2. RC1 EZ Flash rejection and official-image control are historical evidence, not an RC2 flash test.',
            'Native cold/warm boot, actual DXE dispatch and SetupEnter notification delivery with the modified image.',
            'Exact full-IFR matching after any vendor runtime HII updates; mismatch is designed to stop BMC access rather than bind another resource.',
            'GUI visibility/repainting of updated strings, all original pages and OS boot after flashing.',
            'Actual Boot Guard/platform enforcement and complete SPI recovery; no programmer or board-specific SPI backup is available.',
            'Configuration setters and integrated sensor initialization remain absent from this read-only candidate.'],
        analysis_limits=[
            'REA pseudocode is static provider output with the per-record limitations retained; it is not original vendor source or an execution trace.',
            'Two callbacks were absent from automatic procedure discovery. Their link-map entry addresses were supplied as documented seeds in a separate profile; successful seeded records supplement the initial partial batch.',
            'The first sandbox session could not connect to its own local Ghidra bridge (10013); it was cancelled and its verified owned process tree stopped. Only successful permitted-loopback sessions contribute records below.',
            'No live hardware test was performed in this review. Earlier RAM preflight applies to the identical driver bytes, not the new container placement.'],
        records=entries)
    (P/'review-index.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(json.dumps(dict(records=len(entries),rea_used=True,static_container_passed=True,
        candidate_sha256=report['candidate_sha256'],flashback_acceptance_verified=False),indent=2))
if __name__=='__main__':main()
