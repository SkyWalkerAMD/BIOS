"""Fresh local REA session for the extracted ACE CPU_IO2 producer/read path."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
source=HERE.parent/'rea_cold_entry/run_rea.py'
local=HERE/'rea_runner.py'
local.write_bytes(source.read_bytes())
spec=importlib.util.spec_from_file_location('ace06_rea',local)
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
runner.BASE=HERE/'rea';runner.BASE.mkdir(exist_ok=True)
runner.TARGETS={'cpuio2':(HERE/'native/OriginalCpuIo2.efi',[
 ('protocol-producer','0x2d0'),('parameter-validation','0x30c'),('memory-read','0x3d4')],
 [('stride-guid-method-tables','0x700',80)]),
 'cpuio2_tables':(HERE/'native/OriginalCpuIo2.efi',[('memory-read-table-references','0x3d4')],
 [('actual-stride-tables','0x750',32)])}
(HERE/'rea_runner_binding.json').write_text(json.dumps({'copied_runner_sha256':hashlib.sha256(local.read_bytes()).hexdigest(),
 'source':str(source),'wrapper_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},indent=2)+'\n',encoding='utf8')
sys.argv=[str(local),sys.argv[1] if len(sys.argv)>1 else 'cpuio2']
runner.main()
