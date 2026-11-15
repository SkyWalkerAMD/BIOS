"""IPMI-only release and structure guards; this suite never builds a CAP."""
from pathlib import Path
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import build_candidate as build
import verify_candidate as check

ROOT=build.ROOT
R5=ROOT/'analysis/hero_sensor_r5_20261108/HeroIpmiCoreR5.ffs'
OLD_R2=ROOT/'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/R2-sectionfix.ffs'
OLD_R3=ROOT/'analysis/hero_sensor_r3_20261108/HeroIpmiCoreR3.ffs'
OLD_R4=ROOT/'analysis/hero_sensor_r4_20261108/HeroIpmiCoreR4.ffs'
OLD_P6=ROOT/'analysis/hero_ipmi_sectionfix_20261108/candidate-latest/P6-sectionfix.ffs'
OLD_S21=ROOT/'analysis/hero_p6_settings21_20261108/HeroIpmiNativeP6.ffs'
OLD_S21R=ROOT/'analysis/hero_p6_settings21r_20261108/HeroIpmiNativeP6.ffs'
OLD_S21S=ROOT/'analysis/hero_p6_settings21s_20261108/HeroIpmiNativeP6.ffs'
OLD_S22=ROOT/'analysis/hero_p6_s22_20261108/HeroIpmiNativeP6.ffs'
OLD_C04=ROOT/'analysis/hero_ipmi_rc5_s22_20261108/RC5-IPMI-ONLY-R5-S22-CANDIDATE04'
P6_CANDIDATE=ROOT/'analysis/hero_p6_s23_20261108/HeroIpmiNativeP6.ffs'
UNKNOWN='01234567-89ab-cdef-8123-0123456789ab'
def digest(b):return hashlib.sha256(b).hexdigest()
def reheader(data):
    data=bytearray(data);data[20:23]=len(data).to_bytes(3,'little');data[16]=0
    data[16]=-(sum(data[:16])+sum(data[18:23]))&255;return bytes(data)
def entry(path,role,guid):
    raw=path.read_bytes();pe=build.strict_sections(raw[24:])[1][1]
    return dict(path=str(path.relative_to(ROOT)),sha256=digest(raw),pe_sha256=digest(pe),guid=guid,role=role)
def modules():
    return [entry(R5,'sensors_dashboard',build.R2),entry(P6_CANDIDATE,'native_ipmi',build.P6)]

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.good=R5.read_bytes();self.temp=tempfile.TemporaryDirectory(dir=build.HERE,prefix='ipmi-guard-')
        self.path=Path(self.temp.name)/'driver.ffs'
    def tearDown(self):
        assert Path(self.temp.name).resolve().is_relative_to(build.HERE.resolve());self.temp.cleanup()
    def temp_entry(self,data):
        self.path.write_bytes(data)
        e=entry(R5,'sensors_dashboard',build.R2);e['path']=str(self.path.relative_to(ROOT));e['sha256']=digest(data)
        return e
    def reject_set(self,m):
        with self.assertRaises((ValueError,KeyError,TypeError)):build.approved_module_set(m)
        with self.assertRaises((AssertionError,KeyError,TypeError,AttributeError)):check.approved_modules(m)
    def test_exact_frozen_r5(self):
        guid,data,meta=build.driver_artifact(entry(R5,'sensors_dashboard',build.R2))
        self.assertEqual(guid,build.R2);self.assertEqual(meta['pe_bytes'],36864)
        self.assertEqual(meta['sha256'],check.R5_FFS_SHA);self.assertEqual(meta['pe_sha256'],check.R5_PE_SHA)
        check.strict_new_driver(data)
    def test_two_frozen_modules_or_explicit_pending_block(self):
        m=modules()
        if build.P6_RELEASE is None:
            self.assertIsNone(check.P6_RELEASE);self.reject_set(m)
        else:
            self.assertIsNotNone(check.P6_RELEASE)
            build.approved_module_set(m);approved=check.approved_modules(m)
            self.assertEqual(set(approved),{build.R2,build.P6})
            for e in m:build.driver_artifact(e)
    def test_reversed_input_order_preserves_release_policy(self):
        m=modules()[::-1]
        if build.P6_RELEASE is None:self.reject_set(m)
        else:build.approved_module_set(m);check.approved_modules(m)
    def test_independent_constants_match_frozen_r5(self):
        self.assertEqual(build.R5_FFS_SHA,check.R5_FFS_SHA);self.assertEqual(build.R5_PE_SHA,check.R5_PE_SHA)
        self.assertEqual(build.BASELINE_SHA,check.BASELINE_SHA)
        self.assertEqual(digest(build.BASELINE.read_bytes()),check.BASELINE_SHA)
    def test_original_two_byte_tail_regression(self):
        bad=reheader(self.good+b'\0\0')
        with self.assertRaises(ValueError):build.driver_artifact(self.temp_entry(bad))
        with self.assertRaises(ValueError):build.strict_sections(bad[24:])
        with self.assertRaises(AssertionError):check.strict_new_driver(bad)
    def test_bad_checksum(self):
        bad=bytearray(self.good);bad[16]^=1
        with self.assertRaises(ValueError):build.driver_artifact(self.temp_entry(bytes(bad)))
    def test_payload_cannot_self_approve_by_matching_manifest_hash(self):
        bad=bytearray(self.good);bad[-4]^=1;e=self.temp_entry(bytes(bad));e['pe_sha256']='a'*64
        with self.assertRaises(ValueError):build.driver_artifact(e)
        m=modules();m[0]=e;self.reject_set(m)
    def test_changed_ffs_hash(self):
        m=modules();m[0]['sha256']='0'*64;self.reject_set(m)
    def test_changed_pe_hash(self):
        m=modules();m[0]['pe_sha256']='0'*64;self.reject_set(m)
    def test_mismatched_guid(self):
        m=modules();m[0]['guid']=build.P6;self.reject_set(m)
    def test_old_r2_release_rejected(self):
        m=modules();m[0]=entry(OLD_R2,'sensors_dashboard',build.R2);self.reject_set(m)
    def test_old_r3_release_rejected(self):
        m=modules();m[0]=entry(OLD_R3,'sensors_dashboard',build.R2);self.reject_set(m)
    def test_old_r4_release_rejected(self):
        m=modules();m[0]=entry(OLD_R4,'sensors_dashboard',build.R2);self.reject_set(m)
    def test_unknown_p6_hash_rejected(self):
        for key in ('sha256','pe_sha256'):
            m=modules();m[1][key]='f'*64;self.reject_set(m)
    def test_old_native_p6_rejected(self):
        m=modules();m[1]=entry(OLD_P6,'native_ipmi',build.P6);self.reject_set(m)
    def test_pre_refresh_s21_rejected(self):
        m=modules();m[1]=entry(OLD_S21,'native_ipmi',build.P6);self.reject_set(m)
    def test_async_afterboot_s21r_rejected(self):
        m=modules();m[1]=entry(OLD_S21R,'native_ipmi',build.P6);self.reject_set(m)
    def test_pre_portable_s21s_rejected(self):
        m=modules();m[1]=entry(OLD_S21S,'native_ipmi',build.P6);self.reject_set(m)
    def test_single_resource_s22_rejected(self):
        m=modules();m[1]=entry(OLD_S22,'native_ipmi',build.P6);self.reject_set(m)
    def test_c04_manifest_cannot_authorize_s22(self):
        old=json.loads((OLD_C04/'integration-manifest.json').read_text(encoding='utf8'))
        self.reject_set(old['modules'])
    def test_c04_container_rejected_without_changing_old_report(self):
        report=OLD_C04/'independent-container-verification.json';before=report.read_bytes()
        with self.assertRaises(AssertionError):check.verify(OLD_C04.resolve())
        self.assertEqual(report.read_bytes(),before)
    def test_official_comparison_source_independently_pinned(self):
        self.assertEqual(digest(check.OFFICIAL.read_bytes()),check.OFFICIAL_SHA)
    def test_unknown_p6_guid_rejected(self):
        m=modules();m[1]['guid']=UNKNOWN;self.reject_set(m)
    def test_p6_cannot_be_sensor(self):
        m=modules();m[1]['role']='sensors_dashboard';self.reject_set(m)
    def test_inventory_role_rejected(self):
        m=modules();m[1]['role']='inventory';self.reject_set(m)
        with self.assertRaises(ValueError):build.driver_artifact(m[1])
    def test_inventory_new_guid_rejected(self):
        m=modules();m[1].update(role='inventory',guid=UNKNOWN);self.reject_set(m)
    def test_third_module_addition_rejected(self):
        m=modules();m.append(dict(m[1],guid=UNKNOWN,role='inventory'));self.reject_set(m)
    def test_single_sensor_rejected(self):self.reject_set(modules()[:1])
    def test_single_native_rejected(self):self.reject_set(modules()[1:])
    def test_empty_or_malformed_sets_rejected(self):
        for m in ([],{},None,[None,None],[{},{}],['bad','bad']):self.reject_set(m)
    def test_duplicate_sensor_rejected(self):self.reject_set([modules()[0],modules()[0]])
    def test_duplicate_native_rejected(self):self.reject_set([modules()[1],modules()[1]])
    def test_role_renaming_not_authorization(self):
        m=modules();m[0]['role']='native_ipmi';m[1]['role']='sensors_dashboard';self.reject_set(m)
    def test_section_truncation(self):
        for cut in (1,2,3,4):
            with self.assertRaises(ValueError):build.strict_sections(self.good[24:-cut])
            with self.assertRaises(AssertionError):check.strict_new_driver(self.good[:-cut])
    def test_bad_manifest_produces_no_output_directory(self):
        m=modules();m[1]['sha256']='0'*64
        manifest=Path(self.temp.name)/'manifest.json';label='NEGATIVE-NO-OUTPUT-'+Path(self.temp.name).name.upper()
        manifest.write_text(json.dumps(dict(build_id=label,modules=m)))
        expected=build.HERE/label;self.assertFalse(expected.exists())
        with mock.patch.object(build,'guided',side_effect=AssertionError('unexpected compression')):
            with self.assertRaises(ValueError):build.build(manifest)
        self.assertFalse(expected.exists())
    def test_existing_build_directory_is_not_overwritten(self):
        m=modules();label=Path(self.temp.name).name.upper()
        # TemporaryDirectory is lowercase on this host. Use its exact directory
        # through a separate pre-created all-uppercase child of the approved root.
        target=build.HERE/label
        if target.resolve()==Path(self.temp.name).resolve():
            sentinel=Path(self.temp.name)/'keep.txt';sentinel.write_bytes(b'unchanged')
        else:
            target.mkdir();sentinel=target/'keep.txt';sentinel.write_bytes(b'unchanged')
        try:
            manifest=Path(self.temp.name)/'existing.json';manifest.write_text(json.dumps(dict(build_id=label,modules=m)))
            before_names=sorted(p.name for p in target.iterdir())
            with self.assertRaises(ValueError):build.build(manifest)
            self.assertEqual(sentinel.read_bytes(),b'unchanged')
            self.assertEqual(sorted(p.name for p in target.iterdir()),before_names)
        finally:
            if target.resolve()!=Path(self.temp.name).resolve():sentinel.unlink();target.rmdir()
    def test_builder_and_checker_refuse_optimized_python(self):
        for name in ('build_candidate.py','verify_candidate.py'):
            p=subprocess.run([sys.executable,'-I','-S','-B','-O',str(build.HERE/name),'--help'],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0);self.assertIn('Optimized Python',p.stderr)

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(GuardTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    (build.HERE/'builder-guard-tests-ipmi-only-s23.json').write_text(json.dumps(dict(
        passed=result.wasSuccessful(),tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        frozen_r5_sha256=digest(R5.read_bytes()),p6_release_frozen=build.P6_RELEASE is not None,
        no_CAP_generated=True,builder_sha256=digest((build.HERE/'build_candidate.py').read_bytes()),
        checker_sha256=digest((build.HERE/'verify_candidate.py').read_bytes())),indent=2)+'\n')
    raise SystemExit(not result.wasSuccessful())
