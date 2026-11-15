"""Isolated local Ghidra analysis of shipped files; no target execution."""
from pathlib import Path
import importlib.util,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
label=sys.argv[1]
choices={'cdserver':('bin/cdserverapp','.*'),
         'vmedia':('lib/libvmedia.so.13.11.9','^(reset_hdisk_redir|reset_cdrom_redir)$')}
relative,regex=choices[label]
(HERE/'BmcSelectedDecompile.java').write_bytes((REMOTE/'BmcSelectedDecompile.java').read_bytes())
pattern=HERE/(label+'.regex.txt');pattern.write_text(regex,encoding='utf8')
spec=importlib.util.spec_from_file_location('headless',REMOTE/'run_headless.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.HERE=HERE
sys.argv=['run_headless.py',label,str(REMOTE/'media_attach_review02/backend/usr/local'/relative),str(pattern)]
m.main()
