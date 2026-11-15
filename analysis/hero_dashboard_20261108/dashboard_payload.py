"""Pure SMBIOS-to-OEM payload builder matching Creator RVA 0x3A0F4.

No IO/network calls. The BMC Dashboard decoder requires a 4-char BIOS version
and 10-char date; reject rather than silently truncate other representations.
"""
import datetime

def _text(value, maximum):
    if not isinstance(value,str) or not 1<=len(value)<=maximum:
        raise ValueError('invalid identity length')
    if any(not 32<=ord(c)<=126 for c in value):
        raise ValueError('nonprintable identity')
    return value.encode('ascii')+b'\0'

def build(bios_version, bios_date, manufacturer, model, board_version, serial):
    if len(bios_version)!=4 or not bios_version.isascii() or not bios_version.isdigit():
        raise ValueError('BMC requires four digit BIOS version')
    if len(bios_date)!=10 or datetime.datetime.strptime(bios_date,'%m/%d/%Y').strftime('%m/%d/%Y')!=bios_date:
        raise ValueError('BMC requires canonical BIOS date')
    bios=b'\0'+_text(bios_version,4)+_text(bios_date,10)
    board=b'\2'+b''.join(_text(v,n) for v,n in [(manufacturer,32),(model,64),(board_version,32),(serial,32)])
    if len(board)>192:raise ValueError('board request bound')
    return bios,board

def from_records(records):
    found={}
    for r in records:
        if r['type'] not in (0,2):continue
        if r['type'] in found:raise ValueError('duplicate SMBIOS record')
        raw=bytes.fromhex(r['formatted']);strings=r['strings']
        if len(raw)<9 or raw[0]!=r['type'] or raw[1]!=len(raw):raise ValueError('bad formatted record')
        offsets=(5,8) if r['type']==0 else (4,5,6,7)
        values=[]
        for offset in offsets:
            index=raw[offset]
            if not 1<=index<=len(strings):raise ValueError('missing SMBIOS string')
            values.append(strings[index-1])
        found[r['type']]=values
    if set(found)!={0,2}:raise ValueError('missing SMBIOS record')
    return build(*found[0],*found[2])
