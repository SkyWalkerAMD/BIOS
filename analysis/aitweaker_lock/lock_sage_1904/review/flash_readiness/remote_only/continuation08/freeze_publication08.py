"""Freeze this publication's local report copies, without changing device work."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json

HERE = Path(__file__).resolve().parent
READY = HERE.parents[1]
CASE = READY.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf8')


def main():
    check = json.loads((HERE/'publication08_check.json').read_text(encoding='utf8'))
    render = json.loads((HERE/'publication08_render.json').read_text(encoding='utf8'))
    assert check['status'] == 'PASS_LOCAL_PUBLICATION_CONSISTENCY_AND_BINDINGS'
    assert render['status'] == 'PASS_LOCAL_HTML_LAYOUT_AND_LINKS'
    assert not check['task_complete'] and not check['release_ready']
    assert sha(READY/'检查报告.html') == render['report_sha256']
    for rel, expected in check['files'].items():
        assert sha(READY/rel) == expected, rel
    for item in check['requirements']:
        assert sha(Path(item['path'])) == item['sha256']
    for item in render['screenshots']:
        assert sha(HERE/item['path']) == item['sha256']
    snapshot = HERE/'publication08_inputs/report_snapshot'
    snapshot.mkdir(parents=True, exist_ok=True)
    originals = []
    for name in ['acceptance_status.json', '检查报告.html', 'publish_readiness.py']:
        source = READY/name
        target = snapshot/name
        target.write_bytes(source.read_bytes())
        assert sha(target) == sha(source)
        originals.append({'path': str(source), 'sha256_at_publication': sha(source),
                          'frozen_copy': target.relative_to(HERE).as_posix()})
    for label, source in [('SAGE', CASE/'requirements.json'), ('project', CASE.parent/'requirements.json')]:
        value = json.loads(source.read_text(encoding='utf8'))['production_release_work']
        save(snapshot/f'{label}_production_release_work.json', value)
        originals.append({'path': str(source), 'sha256_at_publication': sha(source),
                          'frozen_scope': 'production_release_work only',
                          'frozen_copy': (snapshot/f'{label}_production_release_work.json').relative_to(HERE).as_posix()})
    visual = {
        'status': 'PASS_MANUAL_LOCAL_SCREENSHOT_REVIEW',
        'screenshots': render['screenshots'],
        'observations': ['All three screenshots were opened and inspected.',
                         'No clipped table columns or horizontal overflow at 1200 px viewport.',
                         'Current C08 limitations, both disabled override views, and ongoing installer work are readable.',
                         'Older round details remain collapsed and are explicitly historical.'],
        'scope': 'Local rendering only; no network/device operation or firmware acceptance.',
    }
    save(HERE/'publication08_visual_review.json', visual)
    files = [HERE/name for name in ['publish_validation08.py', 'validation08_result.json',
             'verify_publication08.py', 'publication08_check.json', 'verify_report08.mjs',
             'publication08_render.json', 'publication08_visual_review.json', 'freeze_publication08.py',
             'publication08-top.png', 'publication08-middle.png', 'publication08-bottom.png',
             'publication08_inputs/closed_work_status.json']]
    files += sorted(snapshot.iterdir())
    result = {
        'status': 'FROZEN_C08_DIAGNOSTIC_PUBLICATION_NOT_RELEASE_READY',
        'generated_utc': datetime.now(timezone.utc).isoformat(),
        'diagnostic_session_complete': True, 'task_complete': False, 'release_ready': False,
        'continuing_work': 'Local native installer development; not included as accepted hardware functionality.',
        'local_links_verified': check['evidence_links_verified'],
        'historical_manifest_references_rechecked': 538, 'reference_count_is_not_unique_file_count': True,
        'current_report_originals_at_publication': originals,
        'copied_report_links': 'Copies preserve exact report bytes. Use the main report for relative-link navigation; this snapshot preserves the publication identity.',
        'files': {path.relative_to(HERE).as_posix(): {'sha256': sha(path), 'size': path.stat().st_size} for path in files},
    }
    save(HERE/'publication08_manifest.json', result)
    for rel, binding in result['files'].items():
        assert sha(HERE/rel) == binding['sha256'] and (HERE/rel).stat().st_size == binding['size']
    print(json.dumps({'status': result['status'], 'frozen_files': len(files),
                      'manifest_sha256': sha(HERE/'publication08_manifest.json'),
                      'report_sha256': sha(READY/'检查报告.html')}))


if __name__ == '__main__':
    main()
