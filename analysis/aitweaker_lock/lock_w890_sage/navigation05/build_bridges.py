"""Separate build; never overwrite the tested history/Main component."""
from pathlib import Path
import subprocess,sys,json,hashlib
H=Path(__file__).resolve().parent
build_name='bridges_next'if '--next'in sys.argv else'bridges_build'
subprocess.run([sys.executable,str(H/'visit/make_observer.py')],check=True)
t=(H/'build.py').read_text()
t=t.replace("O=H/'build'","O=H/"+repr(build_name))
t=t.replace("B/'native_observer04/observer.c'","H/'bridges.c',H/'first_bridge.S',H/'visit/observer_visit05.c',H/'visit/restricted_catalog.c'")
t=t.replace("out=O/'W890Navigation05.TESTONLY.dll'","out=O/'W890NavigationBridges05.TESTONLY.dll'")
t=t.replace("assert len(calls)==2,calls","assert len(calls)==5,calls")
t=t.replace("out=O/'W890NavigationBridges05.TESTONLY.dll'","exports += ['n05_bridges_bind','n05_native_render','n05_native_page_input','n05_native_frame_input','n05_native_control_input','n05_native_app_input','n05_native_extra_input','n05_native_alt_input','n05_native_form_open','n05_native_pending','n05_native_first','n05_first_dispatch','n05_recovery_poll','n05_recovery_terminal','n05_first_resume','n05_form_open_trampoline','no_native_visit_identity','no_describe_form_callback']\nout=O/'W890NavigationBridges05.TESTONLY.dll'")
exec(compile(t,str(H/'build.py'),'exec'),{'__file__':str(H/'build.py'),'__name__':'bridges05_build'})
