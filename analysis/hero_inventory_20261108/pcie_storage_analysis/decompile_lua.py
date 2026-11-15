"""Produce convenience pseudocode; bytecode disassembly remains authoritative.

No target Lua is executed. Only the Python decompiler parses its bytes.
"""
from pathlib import Path
import json,subprocess,sys
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
rows=[]
for source in sorted((OUT/'sources').rglob('*.lua')):
 dest=OUT/'decompiled'/source.relative_to(OUT/'sources')
 dest.parent.mkdir(parents=True,exist_ok=True)
 try:
  result=subprocess.run([sys.executable,'-X','utf8',str(ROOT/'tools/luajit-decompiler/main.py'),'-f',str(source),'-o',str(dest),'--with-line-numbers'],capture_output=True,timeout=30)
  dest.with_suffix('.diagnostic.txt').write_bytes(result.stdout+result.stderr)
  rows.append(dict(source=source.relative_to(OUT).as_posix(),returncode=result.returncode,output_exists=dest.exists()))
 except subprocess.TimeoutExpired as ex:
  dest.with_suffix('.diagnostic.txt').write_bytes((ex.stdout or b'')+(ex.stderr or b'')+b'\nTIMEOUT\n')
  rows.append(dict(source=source.relative_to(OUT).as_posix(),timeout=True,output_exists=dest.exists()))
(OUT/'decompile-status.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows,indent=2))
