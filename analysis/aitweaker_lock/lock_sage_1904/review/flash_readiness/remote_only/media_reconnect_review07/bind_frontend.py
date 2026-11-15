"""Static client-side stop evidence; no JS/Java application execution."""
from pathlib import Path
import hashlib,json,subprocess,zipfile
HERE=Path(__file__).resolve().parent;REMOTE=HERE.parent
ROOT=next(p for p in HERE.parents if (p/'tools').is_dir())
MEDIA=REMOTE/'media_writeback_review'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def ref(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def main():
    out=HERE/'frontend';out.mkdir(exist_ok=True)
    inputs=[]
    for name in ['cdrom.js','iusb-scsi.js','media-socket.js']:
        p=MEDIA/'decoded/libs/media'/name;inputs.append(ref(p));(out/name).write_bytes(p.read_bytes())
    viewer=MEDIA/'decoded/viewer.min.js';s=viewer.read_text(encoding='utf8');snippets=[]
    for needle in ['startMedia:function','window.cdrom.sock.onclose=function','sendstopcommandtoserver:function']:
        pos=s.find(needle);assert pos>=0
        snippets.append({'needle':needle,'offset':pos,'snippet':s[pos:pos+2300]})
    jar=MEDIA/'JViewer.jar';javap=Path('D:/JAVA/graalvm-jdk-21.0.9+7.1/bin/javap.exe')
    cp=subprocess.run([str(javap),'-c','-p','-classpath',str(jar),'com.ami.iusb.HarddiskRedir'],capture_output=True,check=True)
    text=cp.stdout.decode('utf8');(out/'HarddiskRedir.javap.txt').write_text(text,encoding='utf8')
    assert 'sipush        247' in text and 'sendCommandToMediaServer' in text
    with zipfile.ZipFile(jar) as z:
        cls=z.read('com/ami/iusb/HarddiskRedir.class')
    helper=REMOTE/'media_writeback_client01/live_writeback04.py'
    engine=REMOTE/'media_writeback_client01/hdmedia_offline.py'
    report={'scope':'No application class or captured JS executed. javap only disassembles the named class.',
            'inputs':inputs+[ref(viewer),ref(jar),ref(helper),ref(engine)],
            'java_class':{'name':'com/ami/iusb/HarddiskRedir.class','bytes':len(cls),'sha256':hashlib.sha256(cls).hexdigest()},
            'viewer_snippets':snippets,
            'opcode_constants':{'F3':'KEEP_ALIVE','F6':'OPCODE_KILL_REDIR','F7':'MEDIA_SESSION_DISCONNECT'},
            'java_normal_stop':'stopRedirection bytecode37..40 sends247/F7,72..78 sets stopRunning then closes owned media socket; send exceptions are logged and closure still continues.',
            'java_abnormal_stop':'stopRedirectionAbnormal bytecode21..27 sets stopRunning and directly calls harddiskDisconnect without F7.',
            'h5_normal_stop':'RemoteControlView.startMedia active branch calls sendstopcommandtoserver (F7), clears cdrom/file and changes UI; no server-side clear-slot acknowledgement awaited.',
            'h5_send_error':'MediaSocket.sendPacket catches send exceptions and logs them, so UI label alone is insufficient proof of server cleanup.',
            'helper04_stop':'STOP/parent EOF ends receive loop; finally engine.stop and socket.close. There is no explicit outgoing F7 on parent_stop.',
            'helper04_start':'IUSBEngine.start emits F2 authentication then F8 media info. Absence of received opcode25 is not evidence that the client omitted F8.'}
    (HERE/'frontend_evidence.json').write_text(json.dumps(report,indent=2),encoding='utf8')
    print({'java_class_sha256':report['java_class']['sha256'],'helper04_sha256':sha(helper)})
if __name__=='__main__':main()
