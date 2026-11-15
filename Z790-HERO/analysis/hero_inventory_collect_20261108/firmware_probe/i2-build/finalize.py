from pathlib import Path
import hashlib,json
P=Path(__file__).resolve().parent;I1=P.parents[1];ROOT=P.parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 b=json.loads((P/'build.json').read_text());v=json.loads((P/'verification.json').read_text());vm=json.loads((P/'vm-verification.json').read_text())
 iso=P/'HERO-FW-ID-I2-READONLY.iso';app=P/'USB/EFI/BOOT/BOOTX64.EFI'
 assert v['passed'] and vm['passed'] and sha(iso)==b['iso_sha256']==v['iso_sha256']==vm['iso_sha256']
 assert sha(app)==b['app_sha256']==v['app_sha256']==vm['app_sha256']
 prior=json.loads((I1/'build.json').read_text());assert sha(I1/'HERO-SMBIOS-I1-READONLY.iso')==prior['iso_sha256']
 copied=json.loads((P/'source-provenance.json').read_text())
 for row in copied:assert sha(ROOT/row['source'])==row['source_sha256']
 report={'version':'HERO FW ID I2','scope':'Offline verification only; ready for user-authorized hardware read-only capture.',
  'iso':str(iso.relative_to(ROOT)),'iso_sha256':sha(iso),'app_sha256':sha(app),'bytes':iso.stat().st_size,
  'source_inputs_unchanged':True,'I1_iso_unchanged':True,'actual_pe_cases_passed':len(v['cases']),'ovmf_passed':True,
  'operation':'Fresh boot, verify HERO FW ID I2 title, F capture, C QR or R text, Esc close viewer, Q then Q exit.',
  'decoder_sha256':sha(P/'decode_captures.py'),'guide_sha256':sha(P/'README.md')}
 (P/'delivery.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
