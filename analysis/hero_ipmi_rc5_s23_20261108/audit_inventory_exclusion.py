"""Read-only official -> baseline -> RC5 comparison and I3/I5 exclusion.

I3 applications and I5 RAM drivers do not currently have FFS file GUIDs.
Do not invent such identifiers or mistake their protocol GUIDs for FFS GUIDs.
The main proof is that all original executable modules are preserved, except
the two pinned IPMI cores; the existing Setup change is resource-only.
"""
from pathlib import Path
import hashlib
import json
import sys
import uuid

if not __debug__:
    raise RuntimeError('This audit requires assertions enabled')
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / 'tools/pydeps'),
               str(ROOT / 'analysis/hero_ipmi_p5_rea_review_20261103')]
import pefile
from container_review import read_image, sections, decode, BASE, SIZE, WRAPPER, SETUP, SPF

R5 = '89924765-f984-4ad3-839b-51fdce378d88'
P6 = '261135b0-7b73-49c0-bcc8-2f9cf4eef19e'
BUILD = 'RC5-IPMI-ONLY-R5-S23-CANDIDATE05'
FILES = {
    'official': (ROOT / 'analysis/hero_3107_official/ROG-MAXIMUS-Z790-HERO-ASUS-3107.CAP',
                 'e900f164cbabec0088ea8f1dd3c0ad932f32a5e14412be814d06cce3a4210f6a'),
    'baseline': (ROOT / 'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/HERO-3107-IPMI-SECTIONFIX-LATEST-UNSIGNED.CAP',
                 '66420b42a5251a1209cac9865d3a1d8d5f1e03e512b4b9ce98ba0d29b81be131'),
    'candidate05': (HERE / BUILD / ('HERO-3107-IPMI-' + BUILD + '-UNSIGNED.CAP'),
                    '68cfc48a76d41f23edf093984818b64a6b13a686956666339733fe0a84e287f9'),
}
PROJECT_API_GUIDS = {
    'dfb7ec4e-5499-4812-a2b7-ab6601f4e505': 'I5a RAM driver API; source/i5.h',
    '7e06fa9a-532e-44c6-928a-cf19d2718e4b': 'I5b/I5c/I5p RAM driver API; variant source/i5.h',
    '9412c522-5b86-4cae-8799-82ee194b9fa5': 'I5b/I5c/I5p trigger protocol; variant source/driver.c',
}
MARKERS = (
    b'HERO-INVENTORY-I3', b'HERO-INVENTORY-I5',
    b'I3D_INVENTORY_STEP', b'I3B_INVENTORY_STEP',
    b'I5_AUTOMATIC_NETWORK_PREPARATION', b'I5_DRIVER_RESIDENT_UNTIL_RESET',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def leaves(blob, depth=0):
    assert depth < 8
    ss = sections(blob)
    assert len(ss) < 4096
    for section in ss:
        if section['type'] == 2:
            plain, _ = decode(section)
            assert len(plain) <= 32 * 1024 * 1024
            yield from leaves(plain, depth + 1)
        else:
            yield section


def setup_image(image):
    ss = list(leaves(image['inner_files'][SETUP]['data'][24:]))
    assert [s['type'] for s in ss] == [0x13, 0x10, 0x14]
    return ss, pefile.PE(data=ss[1]['body'])


def known_project_artifacts():
    """Primary app/core outputs only; omit unmodified original network drivers."""
    families = [ROOT / 'analysis' / name for name in (
        'hero_inventory_publish_20261108', 'hero_inventory_publish_i3a_20261108',
        'hero_inventory_publish_i3b_20261108', 'hero_inventory_publish_i3d_20261108',
        'hero_inventory_i5_20261108')]
    found = {}
    for family in families:
        for path in family.glob('**/USB/EFI/BOOT/*.EFI'):
            if path.name.upper() != 'BOOTX64.EFI' and not path.name.upper().startswith('I5'):
                continue
            raw = path.read_bytes()
            pe = pefile.PE(data=raw)
            assert pe.OPTIONAL_HEADER.Subsystem in (10, 11)
            key = sha(raw)
            found.setdefault(key, dict(sha256=key, bytes=len(raw),
                                      subsystem=pe.OPTIONAL_HEADER.Subsystem, paths=[]))
            found[key]['paths'].append(path.relative_to(ROOT).as_posix())
    assert len(found) >= 8
    return found


def main():
    images = {}
    for name, (path, pin) in FILES.items():
        assert sha(path.read_bytes()) == pin, name
        images[name] = read_image(path)
    official = images['official']
    records = {}
    known = known_project_artifacts()
    official_setup, old_pe = setup_image(official)
    for label in ('baseline', 'candidate05'):
        current = images[label]
        for start, end in ((0, BASE), (BASE + SIZE, len(official['cap']))):
            assert current['cap'][start:end] == official['cap'][start:end]
        changes = {}
        original_unchanged = []
        for layer in ('outer', 'inner'):
            before, after = official[layer + '_files'], current[layer + '_files']
            added, removed = set(after) - set(before), set(before) - set(after)
            assert not removed
            assert added == ({R5, P6} if layer == 'inner' else set())
            changed = [g for g in before if before[g]['data'] != after[g]['data']]
            assert set(changed) == ({SETUP, SPF} if layer == 'inner' else {WRAPPER})
            for guid in before:
                if guid not in changed:
                    original_unchanged.append(dict(layer=layer, guid=guid,
                                                   sha256=sha(after[guid]['data'])))
            changes[layer] = dict(added=sorted(added), removed=[], changed=changed)

        ss, new_pe = setup_image(current)
        assert ss[0]['data'] == official_setup[0]['data']
        assert ss[2]['data'] == official_setup[2]['data']
        assert new_pe.OPTIONAL_HEADER.AddressOfEntryPoint == old_pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x500
        assert len(new_pe.sections) == len(old_pe.sections) == 6
        setup_sections = []
        for old, new in zip(old_pe.sections, new_pe.sections):
            assert old.Name == new.Name and old.Characteristics == new.Characteristics
            if old.Name != b'.rsrc\0\0\0':
                assert old.get_data() == new.get_data()
            if old.Name != b'.reloc\0\0':
                assert old.VirtualAddress == new.VirtualAddress
            setup_sections.append(dict(name=old.Name.rstrip(b'\0').decode('ascii'),
                                       old_sha256=sha(old.get_data()), new_sha256=sha(new.get_data()),
                                       executable=bool(new.Characteristics & 0x20000000),
                                       byte_identical=old.get_data() == new.get_data()))
        # Unchanged import/exception/TLS/security etc. Only resource size and
        # relocation placement are permitted to differ for expanded resources.
        for i, (old, new) in enumerate(zip(old_pe.OPTIONAL_HEADER.DATA_DIRECTORY,
                                            new_pe.OPTIONAL_HEADER.DATA_DIRECTORY)):
            if i == 2:
                assert old.VirtualAddress == new.VirtualAddress
            elif i == 5:
                assert old.Size == new.Size
            else:
                assert (old.VirtualAddress, old.Size) == (new.VirtualAddress, new.Size)
        spf_leaves = list(leaves(current['inner_files'][SPF]['data'][24:]))
        assert [s['type'] for s in spf_leaves] == [0x18, 0x15]  # Raw HII + UI, no code

        # For the only four non-original files, inspect all uncompressed leaves.
        # All other files and non-DXE regions have already been matched exactly
        # to official3107 above, so no project code can hide in an unchanged file.
        scanned = []
        for guid in (SETUP, SPF, R5, P6):
            for index, section in enumerate(leaves(current['inner_files'][guid]['data'][24:])):
                data = section['body']
                assert sha(data) not in known, (label, guid, 'known inventory PE')
                for marker in MARKERS:
                    assert marker not in data, (label, guid, marker)
                    assert marker.decode('ascii').encode('utf-16-le') not in data
                for api in PROJECT_API_GUIDS:
                    assert uuid.UUID(api).bytes_le not in data, (label, guid, api)
                    for spelling in (api, api.upper()):
                        assert spelling.encode('ascii') not in data
                        assert spelling.encode('utf-16-le') not in data
                scanned.append(dict(guid=guid, section=index, type=section['type'],
                                    bytes=len(data), sha256=sha(data)))
        records[label] = dict(cap_sha256=FILES[label][1], changes_from_official=changes,
                              original_unchanged_ffs_count=len(original_unchanged),
                              original_unchanged_ffs=original_unchanged,
                              all_non_dxe_regions_exact_official=True,
                              setup_entry_rva='0x500', setup_sections=setup_sections,
                              setup_non_resource_sections_identical=True,
                              spf_contains_raw_hii_and_ui_only=True,
                              non_original_leaves_scanned=scanned,
                              known_inventory_pe_and_markers_found=False)
    # Candidate must also retain the exact already-reviewed Setup and SPF bytes.
    for guid in (SETUP, SPF):
        assert images['baseline']['inner_files'][guid]['data'] == images['candidate05']['inner_files'][guid]['data']
    result = dict(passed=True, scope='Project I3/I5 publishers excluded from baseline and CANDIDATE05',
                  no_project_inventory_publisher=True,
                  i3_i5_ffs_guids_assigned=False,
                  guid_note='I3 is an EFI application and I5 variants are RAM-only EFI drivers; their API GUIDs are not FFS GUIDs.',
                  only_added_file_guids_relative_to_official=[R5, P6],
                  api_fingerprints=PROJECT_API_GUIDS,
                  markers=[s.decode('ascii') for s in MARKERS],
                  known_project_pe_artifacts=list(known.values()), images=records,
                  native_official_network_drivers_not_claimed_absent=True,
                  hardware_operation_performed=False)
    destination = HERE / 'inventory-exclusion.json'
    destination.write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
    print(json.dumps(dict(passed=True, path=str(destination), sha256=sha(destination.read_bytes()),
                          known_project_pe_artifacts=len(known),
                          unchanged_original_ffs={k:v['original_unchanged_ffs_count'] for k,v in records.items()}), indent=2))


if __name__ == '__main__':
    main()
