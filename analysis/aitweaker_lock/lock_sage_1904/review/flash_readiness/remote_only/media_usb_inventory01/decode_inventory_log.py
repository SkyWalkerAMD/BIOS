"""Parse USBINV01 diagnostic logs; data only, never instructions/actions."""
import re
def parse(log):
    if not isinstance(log,bytes) or not 0<len(log)<32768:raise ValueError('log size')
    text=log.decode('ascii');lines=text.split('\r\n')
    if not text.startswith('MEDIA-USB-INVENTORY-01 EXISTING PROTOCOL METADATA ONLY\r\n') or not text.endswith('PROBE_COMPLETE\r\n'):raise ValueError('identity/footer')
    def one(key):
        v=re.findall(r'^'+re.escape(key)+r'=([0-9A-F]+)\r?$',text,re.M)
        if len(v)!=1:raise ValueError('missing/duplicate '+key)
        return int(v[0],16)
    overflow=one('LOG_OVERFLOW');complete=one('INVENTORY_COMPLETE');reported=one('HANDLES_REPORTED');union=one('HANDLE_UNION_COUNT') if 'HANDLE_UNION_COUNT=' in text else 0
    if overflow not in (0,1) or complete not in (0,1) or reported>union or union>128:raise ValueError('summary bounds')
    if complete and (overflow or reported!=union or one('ENUMERATION_UNCERTAIN') or one('TEST_STATUS')):raise ValueError('false complete')
    if overflow and ('INVENTORY_PARTIAL=1\r\n' not in text or complete):raise ValueError('overflow not explicit')
    rows=[];row=None
    for line in lines:
        if line.startswith('HANDLE_BEGIN='):
            if row is not None:raise ValueError('nested handle')
            row={'index':int(line.split('=',1)[1],16)}
        elif line.startswith('HANDLE_END='):
            if row is None or int(line.split('=',1)[1],16)!=row['index']:raise ValueError('handle boundary')
            rows.append(row);row=None
        elif row is not None and '=' in line:
            key,value=line.split('=',1)
            if key=='PROTOCOL_UNCERTAIN' and row.get(key)==value=='1':continue
            if key in row:raise ValueError('duplicate field')
            row[key]=value
    if row is not None and not overflow:raise ValueError('unfinished handle')
    if len(rows)!=reported or [r['index'] for r in rows]!=list(range(reported)):raise ValueError('reported handles')
    for r in rows:
        if r.get('DP_VALID')=='1':
            raw=bytes.fromhex(r['DP_HEX'])
            if len(raw)!=int(r['DP_BYTES'],16) or not 4<=len(raw)<=2048 or raw[-4:]!=b'\x7f\xff\4\0':raise ValueError('path binding')
        if r.get('USB_DEVICE_VALID')=='1':
            raw=bytes.fromhex(r['USB_DEVICE_HEX'])
            if len(raw)!=18 or raw[:2]!=b'\x12\1' or int(r['USB_VID'],16)!=int.from_bytes(raw[8:10],'little') or int(r['USB_PID'],16)!=int.from_bytes(raw[10:12],'little'):raise ValueError('descriptor binding')
            match=int.from_bytes(raw[8:10],'little')==0x46b and int.from_bytes(raw[10:12],'little')==0xff31
            if int(r['VENDOR_HD_ID_MATCH'],16)!=match:raise ValueError('vendor id marker')
    return {'complete':bool(complete),'overflow':bool(overflow),'reported':reported,'union':union,'test_status':f'{one("TEST_STATUS"):016X}','handles':rows,'partial_tail':row is not None}
