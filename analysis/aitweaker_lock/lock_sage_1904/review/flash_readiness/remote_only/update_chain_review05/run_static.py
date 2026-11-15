"""Redirect installed Ghidra helper into this isolated review directory."""
from pathlib import Path
import importlib.util,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
source=HERE.parent/'BmcSelectedDecompile.java'
target=HERE/source.name
if target.exists():assert target.read_bytes()==source.read_bytes()
else:target.write_bytes(source.read_bytes())
spec=importlib.util.spec_from_file_location('headless_runner',HERE.parent/'run_headless.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.HERE=HERE
m.main()
