"""Disassemble only bounded virtual-media reconnect/cleanup code, offline."""
from pathlib import Path
import hashlib,importlib.util,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
spec=importlib.util.spec_from_file_location('reader',REMOTE/'update_chain_review05/inspect_chain.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def main():
    source=REMOTE/'media_attach_review02/backend/usr/local'
    selected={
        'hdserver':('bin/hdserverapp',[(0x1506c,0x16ca4,'hdserver_loop'),(0x149e4,0x14ea0,'session_cleanup'),
                    (0x17054,0x17320,'receive_packet'),(0x13770,0x13838,'no_media_response'),
                    (0x12e68,0x130b4,'dispatch_response'),(0x17de0,0x17dec,'disconnect_udc'),
                    (0x17dec,0x180b4,'hdisk_start'),(0x180b4,0x181ec,'hdisk_stop'),
                    (0x14234,0x14720,'worker')]),
        'cdserver':('bin/cdserverapp',[(0x1460c,0x1623c,'cdserver_loop'),(0x13f58,0x14450,'session_cleanup'),
                    (0x167e0,0x16acc,'receive_packet'),(0x17564,0x17570,'disconnect_udc'),
                    (0x1777c,0x178c4,'cdrom_stop')]),
        'gadget':('lib/libusbgadget.so.13.31.13',r'^(hdisk_stop|cdrom_stop|vmedia_hd_disconnect|vmedia_cd_disconnect)$'),
        'vmedia':('lib/libvmedia.so.13.11.9',r'^(reset_hdisk_redir|reset_cdrom_redir)$'),
        'nbd':('lib/libnbd.so.13.4.3',r'^nbd_disconnect$')}
    report={}
    for label,(relative,pattern) in selected.items():
        p=source/relative;e=m.Elf32(p);dest=HERE/'disassembly'/label;dest.mkdir(parents=True,exist_ok=True)
        symbols=([{'name':name,'va':start,'size':end-start} for start,end,name in pattern]
                 if isinstance(pattern,list) else m.functions(e,pattern))
        entries=[]
        for sym in symbols:
            row,txt=m.disassemble(e,sym);entries.append(row);(dest/(sym['name']+'.txt')).write_text(txt,encoding='utf8')
        report[label]={'path':str(p),'bytes':len(e.data),'sha256':hashlib.sha256(e.data).hexdigest(),'functions':entries}
    (HERE/'native_analysis.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print({k:len(v['functions']) for k,v in report.items()})
if __name__=='__main__':main()
