"""Pure bounded decoders for a FUTURE read-only PCI/block metadata capture.

This module has no network, firmware, registry, subprocess, or write API.
Output is observations, NEVER authorization to POST inventory.
PCI layout: retained EDK2 Pci22.h; PCIe masks: retained Linux pci_regs.h.
Device path: retained EDK2 DevicePath.h. No PCI BAR sizing writes are needed.
"""
import hashlib
import struct

class CaptureError(ValueError): pass

def uint(value,bits,name):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise CaptureError('invalid '+name)
    return value

def decode_pci(raw,segment,bus,device,function):
    if not isinstance(raw,bytes) or len(raw)!=256: raise CaptureError('require exact 256-byte config snapshot')
    uint(segment,16,'segment');uint(bus,8,'bus');uint(device,5,'device');uint(function,3,'function')
    vendor,product=struct.unpack_from('<HH',raw)
    if vendor in (0,65535): raise CaptureError('absent or invalid vendor ID')
    header=raw[14]&127
    result={'bdf':f'{segment:04X}:{bus:02X}:{device:02X}.{function}',
            'config_sha256':hashlib.sha256(raw).hexdigest(),
            'vendor_id':f'0x{vendor:04X}','device_id':f'0x{product:04X}',
            'class_code':f'0x{int.from_bytes(raw[9:12],"little"):06X}',
            'revision_id':f'0x{raw[8]:02X}','header_type_raw':header,
            'multifunction_header_bit':bool(raw[14]&128),
            'physical_slot':None,'device_type':None,'function_type':None,
            'publication_allowed':False,'capabilities':[],'warnings':[]}
    # Type-1 offsets 0x2c/0x2e describe bridge address ranges, not subsystem IDs.
    if header==0:
        result.update(subsystem_vendor_id=f'0x{int.from_bytes(raw[44:46],"little"):04X}',
                      subsystem_id=f'0x{int.from_bytes(raw[46:48],"little"):04X}')
    elif header==1:
        result['bridge_bus_raw']={'primary':raw[24],'secondary':raw[25],'subordinate':raw[26]}
    else:
        result['warnings'].append('Header type not supported for capability decoding')
        return result
    if not raw[6]&16:return result
    pos=raw[52];seen=set();pcie=[]
    for _ in range(48):
        if pos==0:break
        if pos in seen or not 64<=pos<=252 or pos%4:raise CaptureError('invalid or cyclic capability chain')
        seen.add(pos);ident,nxt=raw[pos:pos+2]
        result['capabilities'].append({'offset':pos,'id':ident})
        if ident==16:
            if pos+4>256:raise CaptureError('truncated PCIe header')
            flags=int.from_bytes(raw[pos+2:pos+4],'little')
            port=(flags>>4)&15;entry={'offset':pos,'version_raw':flags&15,'port_type_raw':port}
            # RC-integrated endpoints/event collectors have no ordinary link.
            if port in (0,1,4,5,6,7,8):
                if pos+20>256:raise CaptureError('truncated PCIe link registers')
                cap=int.from_bytes(raw[pos+12:pos+16],'little');sta=int.from_bytes(raw[pos+18:pos+20],'little')
                entry.update(max_speed_raw=cap&15,max_lanes_raw=(cap>>4)&63,
                             speed_raw=sta&15,lanes_raw=(sta>>4)&63,training=bool(sta&0x800))
            pcie.append(entry)
        pos=nxt
    else:
        if pos:raise CaptureError('capability traversal bound reached')
    if len(pcie)>1:raise CaptureError('duplicate PCIe capability')
    if pcie:result['pcie']=pcie[0]
    return result

def decode_path(raw):
    if not isinstance(raw,bytes) or not 4<=len(raw)<=4096:raise CaptureError('invalid device path bound')
    nodes=[];pos=0;tags=[];namespace=None
    for _ in range(64):
        if pos+4>len(raw):raise CaptureError('missing device path end')
        typ,sub,size=struct.unpack_from('<BBH',raw,pos)
        if size<4 or pos+size>len(raw):raise CaptureError('invalid node size')
        node={'offset':pos,'type':typ,'subtype':sub,'bytes':size}
        if typ==127:
            if sub!=255 or size!=4 or pos+4!=len(raw):raise CaptureError('unsupported multiple or nonterminal device path end')
            nodes.append(node)
            return {'sha256':hashlib.sha256(raw).hexdigest(),'nodes':nodes,'tags':tags,'namespace':namespace}
        if typ==1 and sub==1:
            if size!=6:raise CaptureError('invalid PCI device path length')
            node.update(function=raw[pos+4],device=raw[pos+5])
            if node['function']>7 or node['device']>31:raise CaptureError('invalid PCI path address')
        if typ==3 and sub in (5,15,16):tags.append('usb')
        if typ==3 and sub==18:
            if size!=10:raise CaptureError('invalid SATA path length')
            tags.append('sata');node.update(hba_port=int.from_bytes(raw[pos+4:pos+6],'little'),port_multiplier=int.from_bytes(raw[pos+6:pos+8],'little'),lun=int.from_bytes(raw[pos+8:pos+10],'little'))
        if typ==3 and sub==23:
            if size!=16 or namespace is not None:raise CaptureError('invalid NVMe namespace path')
            tags.append('nvme');namespace={'id':int.from_bytes(raw[pos+4:pos+8],'little'),'uuid_hex':raw[pos+8:pos+16].hex().upper()}
            if namespace['id'] in (0,0xffffffff):raise CaptureError('invalid namespace ID')
        if typ==4 and sub==1:tags.append('partition')
        if typ==4 and sub==2:tags.append('cdrom')
        nodes.append(node);pos+=size
    raise CaptureError('device path node bound reached')

def block_observation(media,raw_path):
    """Capacity of a firmware block address space, not necessarily a physical disk."""
    path=decode_path(raw_path)
    for name in ('media_present','logical_partition','removable','read_only'):
        if type(media.get(name)) is not bool:raise CaptureError('invalid '+name)
    last=uint(media.get('last_block'),64,'last_block');size=uint(media.get('block_size'),32,'block_size')
    uint(media.get('media_id'),32,'media_id')
    if size==0 or size>16*1024*1024 or size&(size-1):raise CaptureError('invalid block size')
    capacity=None
    if media['media_present']:
        capacity=(last+1)*size
        if capacity>0xffffffffffffffff:raise CaptureError('capacity exceeds uint64')
    reasons=[]
    if not media['media_present']:reasons.append('no_media')
    if media['logical_partition'] or 'partition' in path['tags']:reasons.append('partition')
    if 'usb' in path['tags'] or 'cdrom' in path['tags']:reasons.append('external_or_virtual_media')
    if media['removable']:reasons.append('removable_media')
    if not {'nvme','sata'}.intersection(path['tags']):reasons.append('physical_transport_not_proven')
    return {'media':dict(media),'device_path':path,'address_space_capacity_bytes':capacity,
            'identity_collection_candidate':not reasons,'exclusions':reasons,
            'publication_allowed':False,'physical_drive_capacity_bytes':None,
            'note':'A namespace, RAID logical volume, partition, or virtual device must not be labeled a physical drive from BlockIo capacity alone.'}
