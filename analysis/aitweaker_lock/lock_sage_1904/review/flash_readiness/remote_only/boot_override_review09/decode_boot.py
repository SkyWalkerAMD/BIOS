"""Static bytecode decoding, reusing the existing local decoder runner."""
from pathlib import Path
import importlib.util,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('static_decoder',HERE.parent/'bmc_restart_review01/decompile_lua.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.HERE=HERE;m.PREFIX=HERE/'official_inputs/5308416/usr/local'
m.SELECT={
 'system':'redfish/redfish/system.lua',
 'system_access':'redfish/redfish/property-access/ComputerSystem.lua',
 'system_sd_access':'redfish/redfish/property-access/ComputerSystem-SD.lua',
 'ipmi_boot':'sync-agent/extensions/ipmi/libipmi/bootOptions.lua',
 'ami_boot':'sync-agent/extensions/ami/libipmi_ami/bootOptions.lua',
 'init_boot':'sync-agent/extensions/ipmi/init_agent_scripts/init-boot.lua',
 'chassis':'sync-agent/extensions/ipmi/sync-helpers/Chassis.lua',
 'intermediate_map':'sync-agent/extensions/ipmi/redfish_intermediate_map.lua'}
if __name__=='__main__':m.main()
