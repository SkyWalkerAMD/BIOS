"""Independent read-only investigation of FD01's first observed busy state.

Does not patch/build a candidate or access any device. Runs the existing EFI
core in Unicorn with the already existing synthetic harness, then evaluates a
strict proposed polling predicate as a design model (not compiled firmware).
"""
from pathlib import Path
import datetime, hashlib, importlib.util, json, sys

HERE = Path(__file__).resolve().parent
REMOTE = HERE.parent
CASE = REMOTE.parents[2]
CANDIDATE = REMOTE / 'spi_descriptor_candidate01'
LOG = CASE / 'remote_172_20_2_162/hardware-spifd01-1793681107320/hardware-log.txt'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bind(path):
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def old_valid(s, allow_busy):
    return ((s & 0xffd8) == 0xe800 and not (s & 6)
            and not (s & 0xc0e10000) and ((s >> 17) & 15) <= 8
            and (allow_busy or not (s & 0x20)))


def proposed_poll(s):
    # Exact additional state, not a global removal of the FGO prohibition.
    # Restrict BUSY+DONE as ambiguous. No write action exists in this model.
    if s in (0x3f00e820, 0x3f01e820, 0x3f00e800):
        return 'wait_read_only'
    if s == 0x3f00e801:
        return 'complete_read_data_allowed'
    return 'stop_no_more_mmio_writes'


def main():
    assert sha(CANDIDATE / 'build/BOOTX64.EFI') == '20a9c111dc048805b62261bdee7438a573a0a5a2846d2a57bc4f6cfbda4c3c48'
    assert sha(LOG) == 'fa3a1d6c11c2787d7fed3740c707f422dbfe2a39464a6271b3d6f111c948f19a'
    assert 'LAST_STATUS=0x3F01E820' in LOG.read_text()
    spec = importlib.util.spec_from_file_location('fd01_unmodified_core_harness', CANDIDATE / 'verify_core.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    replay = module.execute('observed_first_poll_GO1_SCIP1', poll_corrupt_at=1,
                            poll_xor=0x10000, expected_stage=11)
    assert replay['result']['last_status'] == 0x3f01e820
    assert replay['result']['writes'] == 2 and replay['result']['go_attempts'] == 1
    assert replay['result']['blocks'] == replay['result']['passes'] == 0
    assert replay['result']['final_transients_restored'] == 0

    model_cases = []
    def check(name, word, expected):
        result = proposed_poll(word)
        assert result == expected, (name, hex(word), result, expected)
        model_cases.append({'name': name, 'word': f'0x{word:08X}', 'result': result, 'passed': True})
    for name, word, expected in [
        ('observed_busy_GO1', 0x3f01e820, 'wait_read_only'),
        ('documented_model_busy_GO0', 0x3f00e820, 'wait_read_only'),
        ('pending_no_done_no_busy', 0x3f00e800, 'wait_read_only'),
        ('strict_complete', 0x3f00e801, 'complete_read_data_allowed'),
        ('idle_GO1', 0x3f01e800, 'stop_no_more_mmio_writes'),
        ('idle_GO1_DONE1', 0x3f01e801, 'stop_no_more_mmio_writes'),
        ('busy_GO1_DONE1', 0x3f01e821, 'stop_no_more_mmio_writes'),
        ('busy_GO0_DONE1', 0x3f00e821, 'stop_no_more_mmio_writes'),
    ]:
        check(name, word, expected)
    for base in (0x3f01e820, 0x3f00e801):
        for bit in range(32):
            word = base ^ (1 << bit)
            if word not in (0x3f00e820, 0x3f01e820, 0x3f00e800, 0x3f00e801):
                check(f'single_bit_change_{base:08x}_{bit}', word, 'stop_no_more_mmio_writes')

    report = {
        'status': 'OBSERVED_BUSY_FGO_FALSE_REJECTION_REPRODUCED_MINIMAL_POLL_DESIGN_SUPPORTED_WITH_LIMITS',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Independent offline analysis only; no BMC/device access, no source/candidate patch, no firmware update.',
        'observed': {
            'log': bind(LOG), 'last_status': '0x3F01E820',
            'decode': {'FDBC': 63, 'bytes_requested': 64, 'FCYCLE': 0, 'FGO': 1, 'SCIP': 1,
                       'FDONE': 0, 'FCERR': 0, 'AEL': 0, 'fixed_lock_status': '0xE800'},
            'reported_mmio_calls': {'read': 25, 'write': 2, 'GO_attempts': 1},
            'reported_completed_blocks': 0, 'descriptor_exported': False,
            'boundary': 'One post-start observation. No later busy/completion state was observed; this does not prove the cycle completed or FGO eventually cleared.'
        },
        'references': {
            'intel_pdf': bind(HERE / 'Intel-743845-001.pdf'),
            'visual_page_399': bind(HERE / 'Intel-registers-0399.png'),
            'intel_page_399': {
                'FGO': 'Writing one requests the cycle; the description says hardware clears on arbiter grant and also specifies zero on reads. The observed FGO=1 is a documented-versus-observed discrepancy, not something this datasheet explicitly guarantees.',
                'SCIP': 'Set when software starts FGO; remains set through the SPI cycle. The description uses its clearing to determine valid read data and eligibility for a next command.',
                'write_rule': 'Do not change the sequencing register while the current transaction is in progress.'
            },
            'linux_source': bind(REMOTE / 'read_only_backup_design/references/linux-spi-intel.c'),
            'linux_primary_url': 'https://github.com/torvalds/linux/blob/6628e7d4c6b25c8d18f1345e3a20d21829aae7e4/drivers/spi/spi-intel.c',
            'linux_exact_lines': {
                '319-326': 'intel_spi_wait_hw_busy polls SCIP only and does not reject busy FGO=1.',
                '575-583': 'READ path programs address then FDBC and READ/FGO in a DWORD transaction.',
                '585-600': 'Waits for SCIP to clear, then checks FCERR and AEL before reading data; does not require FGO=0 or FDONE=1. Proposed bounded candidate remains stricter at completion.'
            },
            'flashrom_source': bind(REMOTE / 'read_only_backup_design/references/flashrom-ichspi.c'),
            'flashrom_exact_lines': {
                '1337-1346': 'Hardware polling reads status for DONE/FCERR, not the FGO control field.',
                '1374-1394': 'Programs HSFC FGO once with fixed transaction fields.',
                '1397-1403': 'Checks SCIP is clear before a new transaction.'
            }
        },
        'root_cause_in_current_candidate': {
            'source': bind(CANDIDATE / 'source/fd_core.c'),
            'lines_35_37': 'status_valid rejects bit16 through mask 0xC0E10000, including the busy polling call.',
            'line_89': 'The additional exact upper-word requirement 0x3F000000 independently rejects the same observed FGO bit.',
            'both_gates_reject_observation': (not old_valid(0x3f01e820, True)) and (0x3f01e820 & 0xffff0000 != 0x3f000000),
            'original_synthetic_model_gap': 'verify_core.py asserted FGO reads as zero immediately after GO. Its poll_changed_bit_16 test intentionally expected rejection; real hardware supplied exactly that state. No fabricated completion is implied by existing PASS reports.',
            'compiled_replay': replay,
            'replay_harness': bind(CANDIDATE / 'verify_core.py'),
            'efi': bind(CANDIDATE / 'build/BOOTX64.EFI')
        },
        'minimal_design_only': {
            'extra_allowed_observation': '0x3F01E820, and only in the post-GO bounded poll phase.',
            'preserved': ['Exactly one fixed READ64 start per block.', 'No writes during polling, timeout or ambiguous completion.',
                          '10000 polls / existing 10us stalls and stop on all I/O errors.',
                          'Same lock/error/reserved/cycle/length validation.',
                          'Only completion 0x3F00E801 enables FDATA reads.',
                          'Initial/idle/acknowledgement/restoration paths still require FGO=0.',
                          'Existing address/protection checks, two-pass match, and output gates.'],
            'do_not': ['Do not erase bit16 globally before validating status.', 'Do not send another GO or perform cleanup after timeout.',
                       'Do not accept FGO1 with SCIP0 as completion.', 'Do not use a preliminary delay solely to hide the first observed state.',
                       'Do not claim this resolves a physical controller issue before a separately bounded hardware observation.'],
            'model_case_count': len(model_cases), 'model_cases': model_cases,
            'model_limit': 'Pure predicate design checks; no proposed candidate was built or executed by this review.'
        },
        'required_candidate_verification': [
            'Replay exact observed busy word then strict completed word with real compiled core and native CPU_IO2 harness.',
            'Test repeated GO1+SCIP1 until timeout; require one GO, zero completed blocks, no extra writes.',
            'Reject GO1+SCIP0, GO1+DONE1, errors, cycle/length/lock changes; no data export.',
            'Confirm all previous idle/control write whitelist and fail-stop regression coverage remains valid.',
            'Record at least first busy and final completion status in future diagnostic output without adding writes.'
        ],
        'limits': ['Current log alone cannot show eventual completion or rule out another firmware actor.',
                   'Linux poll practice supports tolerating the observation, not proof of target acceptance.',
                   'No full SPI backup, recovery, or flash-update acceptance is established.'],
        'review_script': bind(Path(__file__))
    }
    dest = HERE / 'fd01_busy_transition_review.json'
    dest.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'report': str(dest), 'sha256': sha(dest), 'predicate_cases': len(model_cases)}))


if __name__ == '__main__':
    main()
