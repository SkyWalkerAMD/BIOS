"""Direct offline Ghidra fallback; never run target BMC code on the host."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
TARGETS={
 'comp':('libcompamibios.so.13.3.0',['verify_bios_signature','bios_start_update','bios_prepare_comp','bios_flash','bios_backup_image','do_bios_recovery','flash_bios_image','verify_bios_img','BiosConfiguration']),
 'pdk':('libipmipdk.so.13.39.0',['PDK_VerifyBiosSignature','PDK_ASUSBIOSConfiguration','PDK_GetASUSBIOSInfo','PDK_SwitchBIOSFlash','PDK_HostSPIFlashHook']),
 'pdkapp':('libpdkapp.so.13.19.0',['PDK_VerifyBiosSignature','PDK_ASUSBIOSConfiguration','PDK_GetASUSBIOSInfo','PDK_SwitchBIOSFlash','PDK_HostSPIFlashHook']),
 'pdkapp_io':('libpdkapp.so.13.19.0',['read_file_append','read_file']),
 'flash':('libflash.so.13.37.0',['flash_bios_image','verify_bios_img','asus_find_bios_spi_device','asus_bios_preserve_init','read_bios_image']),
 'host':('libhosthelper.so.13.7.0',['flash_bios_image','verify_bios_img','asus_find_bios_spi_device','copybiosImage']),
 'manager':('libcomponent_manager.so.13.23.0',['CMD_Verify_BIOS_Signature','CMD_Prepare_FW_Update','CMD_Start_Firmware_Update']),
 'rest':('spx_restservice',['VerifySignature_func','VerifySignature','putBIOSStartFlashMode_func','setBIOSPrepareComponents_func','uploadBIOSFWImage_func','uploadBIOSSignature_func']),
}

def main():
    key=sys.argv[1];name,names=TARGETS[key]
    run=HERE/'ghidra_backend'/key;run.mkdir(parents=True,exist_ok=True)
    if (run/'analysis.json').exists(): raise ValueError('Analysis already exists: reuse it or select a new explicit investigation')
    env=os.environ.copy();env['JAVA_HOME']='D:/JAVA/graalvm-jdk-21.0.9+7.1'
    env['JAVA_TOOL_OPTIONS']='-Duser.home='+str(run/'userhome')+' -Dapplication.settingsdir='+str(run/'config')+' -Dapplication.cachedir='+str(run/'cache')
    env['XDG_CONFIG_HOME']=str(run/'config')
    env['GHIDRA_HEADLESS_MAXMEM']='2048M';env['TEMP']=str(run/'tmp');env['TMP']=env['TEMP']
    for sub in ['userhome','tmp','project','config','cache']: (run/sub).mkdir(exist_ok=True)
    target=HERE/'backend_inputs'/name
    projectkey={'pdkapp_io':'pdkapp'}.get(key,key)
    projectdir=HERE/'ghidra_backend'/projectkey/'project'
    selection=['-process',name,'-noanalysis'] if (projectdir/('offline_'+projectkey+'.gpr')).exists() else ['-import',str(target)]
    args=[str(ROOT/'tools/rea-runtime/ghidra_12.1.4_PUBLIC/support/analyzeHeadless.bat'),str(projectdir),'offline_'+projectkey,
          *selection,'-scriptPath',str(HERE),'-postScript','ExportW890Backend.java',str(run),*names,
          '-analysisTimeoutPerFile','300','-max-cpu','2']
    started=time.time()
    with (run/('console_'+str(time.time_ns())+'.log')).open('wb') as log:
        p=subprocess.Popen(args,env=env,stdout=log,stderr=subprocess.STDOUT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        (run/'process.json').write_text(json.dumps({'pid':p.pid,'args':args,'started':started,'target_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'target_execution':False},indent=2)+'\n')
        code=p.wait(timeout=660)
    result={'key':key,'exitcode':code,'seconds':round(time.time()-started,2),'analysis_exists':(run/'analysis.json').exists()}
    (run/'run.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    if code or not result['analysis_exists']: raise SystemExit(1)

if __name__=='__main__': main()
