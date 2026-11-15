"""Independent S23 PNG decoding using the previously reviewed frame verifier."""
from pathlib import Path
import importlib.util,json,re,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('base_qr_review',HERE/'verify_live_qr.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
# The shared parser expects the protocol prefix as its first capture group.
base.FRAME=re.compile(rb'(HERO-P6-HOST15-S23-QR1)\nT=([0-9]{1,7});C=([0-9A-F]{8});P=([0-9]{1,4})/([0-9]{1,4});O=([0-9]{1,7});N=([0-9]{1,3});D=([0-9A-F]{8})\n\n')
if __name__=='__main__':print(json.dumps([base.verify(n) for n in sys.argv[1:]],indent=2))
