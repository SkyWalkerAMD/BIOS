"""Strict CAP02 data decoder. Never executes text recovered from a QR code."""
import argparse,hashlib,json,re
from pathlib import Path
PIN='02010C00D041030A00000000010106000014030506000C000305060001007FFF0400'
FOOTER='FILE_OPS=0 BLOCK_DATA_OPS=0 RAW_USB_OPS=0 CONNECT_OPS=0\r\nSCSI_WRITE_OPS=0 SCSI_RESET_OPS=0 PASSTHRU_COMMANDS=0 RUNTIME_OPS=0\r\nPROBE_COMPLETE\r\n'
def parse(log):
    if not isinstance(log,bytes) or not 0<len(log)<32768:raise ValueError('log size')
    text=log.decode('ascii')
    if not text.startswith('MEDIA-CAPACITY-02 STANDARD SCSI OWNER ONLY\r\n') or not text.endswith(FOOTER):raise ValueError('identity/footer')
    def value(key,optional=False):
        v=re.findall(r'^'+re.escape(key)+r'=([^\r\n]+)\r?$',text,re.M)
        if optional and not v:return None
        if len(v)!=1:raise ValueError('missing/duplicate '+key)
        return v[0]
    def num(key,optional=False):
        v=value(key,optional)
        if v is None:return None
        if not re.fullmatch('[0-9A-F]+',v):raise ValueError('invalid number '+key)
        return int(v,16)
    overflow=num('LOG_OVERFLOW');complete=num('INVENTORY_COMPLETE');uncertain=num('ENUMERATION_UNCERTAIN');reported=num('HANDLES_REPORTED')
    union=num('HANDLE_UNION_COUNT',True) or 0;commands=num('RC10_COMMANDS');valid=num('RC10_VALID');status=num('TEST_STATUS');targets=num('TARGET_ID_COUNT',True)
    if any(x not in (0,1) for x in [overflow,complete,uncertain,commands,valid]) or reported>union or union>128 or targets is not None and targets>128:raise ValueError('summary bounds')
    if complete and (overflow or uncertain or reported!=union):raise ValueError('false inventory complete')
    if overflow and (value('OBSERVATION_PARTIAL')!='1' or complete or commands):raise ValueError('overflow contract')
    if value('SELECTOR_DP_HEX')!=PIN:raise ValueError('wrong selector')
    rows=[];row=None
    for line in text.split('\r\n'):
        if line.startswith('HANDLE_BEGIN='):
            if row is not None:raise ValueError('nested handle')
            row={'index':int(line.split('=',1)[1],16)}
        elif line.startswith('HANDLE_END='):
            if row is None or int(line.split('=',1)[1],16)!=row['index']:raise ValueError('handle boundary')
            rows.append(row);row=None
        elif row is not None and '=' in line:
            key,v=line.split('=',1)
            if key=='PROTOCOL_UNCERTAIN' and row.get(key)==v=='1':continue
            if key in row:raise ValueError('duplicate handle field '+key)
            row[key]=v
    if row is not None and not overflow:raise ValueError('unfinished handle')
    if len(rows)!=reported or [r['index'] for r in rows]!=list(range(reported)):raise ValueError('reported handles')
    for r in rows:
        if r.get('DP_VALID')=='1':
            raw=bytes.fromhex(r['DP_HEX']);pos=nodes=instances=0
            while pos<len(raw):
                if len(raw)-pos<4:raise ValueError('short path node')
                n=int.from_bytes(raw[pos+2:pos+4],'little');nodes+=1
                if n<4 or pos+n>len(raw) or nodes>64:raise ValueError('path bounds')
                if raw[pos]==0x7f:
                    if n!=4 or raw[pos+1] not in [1,255]:raise ValueError('path end')
                    if raw[pos+1]==1:instances+=1
                    elif pos+n!=len(raw):raise ValueError('early path end')
                pos+=n
            if len(raw)!=int(r['DP_BYTES'],16) or not 4<=len(raw)<=2048 or raw[-4:]!=b'\x7f\xff\4\0' or instances!=int(r['DP_EXTRA_INSTANCES'],16):raise ValueError('path binding')
        if r.get('USB_DESCRIPTORS_VALID')=='1':
            d=bytes.fromhex(r['USB_DEVICE_HEX']);f=bytes.fromhex(r['USB_INTERFACE_HEX'])
            if len(d)!=18 or d[:2]!=b'\x12\1' or len(f)!=9 or f[:2]!=b'\x09\4' or int(r['USB_VID'],16)!=int.from_bytes(d[8:10],'little') or int(r['USB_PID'],16)!=int.from_bytes(d[10:12],'little'):raise ValueError('descriptor binding')
            match=d[8:12]==bytes.fromhex('6B0431FF') and f[5:8]==b'\x08\x06\x50'
            if int(r['TARGET_ID_MATCH'],16)!=match:raise ValueError('target id binding')
    if complete and targets is not None and targets!=sum(r.get('TARGET_ID_MATCH')=='1' for r in rows):raise ValueError('target count')
    blocked=value('RC10_BLOCKED',True);failure=value('RC10_FAILURE',True)
    if commands and (not complete or targets!=1 or blocked is not None):raise ValueError('command authorization')
    if commands:
        ti=num('TARGET_HANDLE_INDEX');oi=num('SCSI_OWNER_HANDLE_INDEX')
        if ti>=len(rows) or oi>=len(rows) or num('SCSI_EXECUTABLE_OWNER_COUNT')!=1:raise ValueError('owner count/index')
        t=rows[ti];o=rows[oi]
        if t.get('TARGET_ID_MATCH')!='1' or t.get('DP_HEX')!=PIN or t.get('DP_EXTRA_INSTANCES')!='00':raise ValueError('target authorization')
        f=bytes.fromhex(t['USB_INTERFACE_HEX'])
        if f[2:5]!=b'\0\0\2':raise ValueError('interface authorization')
        op=bytes.fromhex(o['DP_HEX']);pin=bytes.fromhex(PIN)
        if op not in [pin,pin[:-4]+b'\3\x11\5\0\0'+pin[-4:]] or o.get('SCSI_IO_STATUS')!='0000000000000000':raise ValueError('owner path')
        if value('RC10_CDB')!='25000000000000000000' or num('RC10_TIMEOUT_100NS')!=20000000 or num('RC10_EVENT_NULL')!=1:raise ValueError('command bounds')
    data=None
    if valid:
        if commands!=1 or failure or any(num(k)!=v for k,v in [('RC10_STATUS',0),('RC10_HOST_STATUS',0),('RC10_TARGET_STATUS',0),('RC10_RETURNED_BYTES',8),('RC10_RETURNED_SENSE_BYTES',0),('RC10_GUARDS_OK',1),('RC10_PACKET_INPUTS_UNCHANGED',1)]):raise ValueError('false valid RC10')
        data=bytes.fromhex(value('RC10_DATA_HEX'))
        if len(data)!=8:raise ValueError('capacity length')
        last=int.from_bytes(data[:4],'big');block=int.from_bytes(data[4:],'big')
        if not block or last==0xffffffff or last!=num('RC10_LAST_LBA') or block!=num('RC10_BLOCK_BYTES') or (last+1)*block!=num('RC10_CAPACITY_BYTES'):raise ValueError('capacity binding')
    if status==0 and not valid:raise ValueError('success without capacity')
    return {'complete':bool(complete),'overflow':bool(overflow),'enumeration_uncertain':bool(uncertain),'reported':reported,'union':union,
      'target_count':targets,'command_count':commands,'rc10_valid_response':bool(valid),'rc10_success':bool(valid and status==0),
      'test_status':f'{status:016X}','blocked_reason':blocked,'failure_reason':failure,'capacity_hex':data.hex() if data else None,
      'handles':rows,'partial_tail':row is not None,'log_sha256':hashlib.sha256(log).hexdigest()}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('log',type=Path);p.add_argument('--out',type=Path);args=p.parse_args();r=parse(args.log.read_bytes());s=json.dumps(r,indent=2)
    if args.out:args.out.write_text(s+'\n',encoding='utf8')
    print(s)
