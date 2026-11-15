from pathlib import Path
import importlib.util,sys
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("runner",HERE/"rea_runner.py");runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
runner.BASE=HERE/"rea";runner.BASE.mkdir(exist_ok=True)
runner.TARGETS={"fmp":(HERE.parent/"native_inputs/ReFlash-70e1a818-0.efi",[("fmp-installation","0xa1c"),("fmp-GetImage-unsupported","0x26bc"),("fmp-GetImageInfo","0x26c8"),("fmp-SetImage","0x27b4")],[("fmp-protocol-table","0x7ab0",48),("fmp-guid","0x77d0",16),("fmp-GetImage-exact-bytes","0x26bc",11)])}
sys.argv=[str(HERE/"run_fmp_rea.py"),"fmp"]
runner.main()
