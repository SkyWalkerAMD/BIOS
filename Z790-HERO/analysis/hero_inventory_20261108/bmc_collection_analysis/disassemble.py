"""Decode LuaJIT bytecode as text only; do not execute firmware code."""
from pathlib import Path
import contextlib,hashlib,json,sys
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'tools/luajit-decompiler'))
import main as ljd_main
import ljd.rawdump.parser
import ljd.pseudoasm.writer

def header(h):
 assert h.version in (1,2)
 ljd_main.set_luajit_version(2.0 if h.version==1 else 2.1)

rows=[]
for source in sorted((OUT/'sources').rglob('*.lua')):
 # The installed parser emits raw opcodes to stdout; retain that diagnostic
 # locally instead of flooding the interactive tool output.
 with (OUT/'parser-diagnostics.txt').open('a',encoding='utf-8') as debug:
  with contextlib.redirect_stdout(debug):
   h,p=ljd.rawdump.parser.parse(str(source),header)
 assert p
 dest=OUT/'bytecode'/source.relative_to(OUT/'sources')
 dest=dest.with_suffix('.txt');dest.parent.mkdir(parents=True,exist_ok=True)
 with dest.open('w',encoding='utf-8',newline='\n') as f:
  with (OUT/'writer-opcodes.txt').open('a',encoding='utf-8') as debug:
   with contextlib.redirect_stdout(debug):
    ljd.pseudoasm.writer.write(f,h,p)
 rows.append(dict(source=source.relative_to(OUT).as_posix(),sha256=hashlib.sha256(source.read_bytes()).hexdigest(),output=dest.relative_to(OUT).as_posix()))
(OUT/'bytecode-manifest.json').write_text(json.dumps(rows,indent=2)+'\n')
print('Disassembled',len(rows),'firmware bytecode files; none executed.')
