from pathlib import Path
import sys,importlib.util
sys.dont_write_bytecode=True
p=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location("headless",p.parent/"run_headless.py");m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.HERE=p
sys.argv=["run_headless.py","websocket",str(p.parent/"media_geometry_review06/official_inputs/5308416/usr/local/lib/mod_websocket.so.13.12.6"),str(p/"websocket.regex.txt")]
m.main()
