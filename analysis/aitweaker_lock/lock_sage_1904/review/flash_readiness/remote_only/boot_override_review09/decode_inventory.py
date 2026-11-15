"""Bounded static inventory synchronization decoder."""
from pathlib import Path
import importlib.util,sys,json
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('static_decoder',HERE.parent/'bmc_restart_review01/decompile_lua.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.HERE=HERE;m.PREFIX=HERE/'official_inputs/5308416/usr/local'
m.SELECT={
 'hi_system':'redfish/extensions/host-interface/hi-handlers/system.lua',
 'hi_inventory':'redfish/oem/ami_hi/hi-inventory-data.lua',
 'hi_helper':'sync-agent/extensions/host-interface/hi-inventory-helper.lua'}
if __name__=='__main__':
    original=(HERE/'lua_decode_manifest.json').read_bytes()
    m.main()
    (HERE/'lua_inventory_decode_manifest.json').write_bytes((HERE/'lua_decode_manifest.json').read_bytes())
    (HERE/'lua_decode_manifest.json').write_bytes(original)
