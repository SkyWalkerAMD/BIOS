"""Independent strict reconstruction of D7 packets. Never runs exported data."""
import hashlib,struct,uuid,zlib
CPU='dbf338fe-93be-46d6-adf5-c17c2236d838';UNKNOWN='25fd9f0b-a3ef-4788-a40c-81849d178a6c'
NVME='668706b2-bcfc-4ad4-a185-75e79f3fe169';SOCKET='6b6fd380-2c55-42c6-98bf-cbbc5a9aa666'
BASE_SHA='c11cb470f9aa84eba8a7fc5bf084ca8a1a466290f7c59f4ac3f9474fa684a06a'
BASELINES={CPU:(157,BASE_SHA),NVME:(259,'bd16c4754e0709b4a3a2637788de9025b32ea6f2f4d0dc46424e29bd6da3187e'),SOCKET:(135794,'54a37eacf5f5a10f387039e251dfee4a5be21138f3ae735ac5c9770f87765e7a')}
def baseline_for(target,baseline):
 if target['kind']==2:return None
 return baseline.get(target['package_list_guid']) if isinstance(baseline,dict) else baseline
def u32(p,n):return struct.unpack_from('<I',p,n)[0]
def validate_forms(data):
 if len(data)<4 or len(data)>0xffffff or u32(data,0)!=(len(data)|(2<<24)):raise ValueError('Not exact type2 forms package')
 at=4;depth=sets=count=0
 while at<len(data):
  if at+2>len(data):raise ValueError('Short IFR opcode')
  op=data[at];n=data[at+1]&127;scope=data[at+1]>>7
  if n<2 or at+n>len(data):raise ValueError('IFR length')
  if op==14:
   if n<23 or depth or not scope:raise ValueError('Formset nesting')
   sets+=1
  if op==1:
   if n!=6 or not depth or not scope:raise ValueError('Form framing')
   count+=1
  if op==41:
   if n!=2 or not depth or scope:raise ValueError('End framing')
   depth-=1
  elif scope:
   depth+=1
   if depth>256:raise ValueError('Depth')
  at+=n
 if depth or not sets or not count:raise ValueError('Incomplete forms')
 return count
def decode(packet,baseline,expected_source,expected_selection,capacity,expected_target):
 if len(packet)<224 or len(packet)>capacity or packet[:8]!=b'AITD07\0\0':raise ValueError('Packet extent/magic')
 version,kind=struct.unpack_from('<HH',packet,8)
 if version!=1 or kind not in (1,2,3) or u32(packet,12)!=224 or packet[216:220]!=bytes(4):raise ValueError('Packet version/header')
 if zlib.crc32(packet[:220])!=u32(packet,220):raise ValueError('Header CRC')
 source=packet[48:80];selection=packet[80:112]
 if source!=expected_source or selection!=expected_selection or not any(source) or not any(selection):raise ValueError('Collection/selection binding')
 g=str(uuid.UUID(bytes_le=packet[32:48]));artifact,index=struct.unpack_from('<II',packet,16);hii=struct.unpack_from('<Q',packet,24)[0]
 bn,n,pre,suf,body_n,body_crc,total,flags,instances,instance_index=struct.unpack_from('<10I',packet,176)
 if not artifact or not hii or not 1<=instances<=4096 or instance_index>=instances or total!=len(packet) or body_n!=len(packet)-224:raise ValueError('Packet lengths/identity')
 if (kind!=expected_target['kind'] or g!=expected_target['package_list_guid'] or index!=expected_target['package_index'] or
     n!=expected_target['result_bytes'] or packet[144:176].hex()!=expected_target['result_sha256'] or
     instances!=expected_target['expected_instances'] or artifact!=expected_target['artifact_base']+instance_index):raise ValueError('Selected target fingerprint/instance binding')
 if flags&~7 or not flags&1:raise ValueError('Diagnostic flags')
 body=packet[224:]
 if zlib.crc32(body)!=body_crc:raise ValueError('Body CRC')
 if kind in (1,3):
  if g not in BASELINES or (kind==1)!=(g==CPU):raise ValueError('Fixed baseline identity')
  expected_n,expected_sha=BASELINES[g]
  if bn!=expected_n or baseline is None or len(baseline)!=expected_n or hashlib.sha256(baseline).hexdigest()!=expected_sha or packet[112:144].hex()!=expected_sha:raise ValueError('Fixed baseline binding')
  if flags&4 or n<4 or n>0xffffff or pre>bn-4 or suf>bn-4-pre or 4+pre+body_n+suf!=n:raise ValueError('Delta copy bounds')
  result=struct.pack('<I',n|(2<<24))+baseline[4:4+pre]+body+(baseline[bn-suf:] if suf else b'')
  text_only=(kind==1 and n>=157 and (n-157)%8==0 and result[4:132]==baseline[4:132] and result[-25:]==baseline[132:] and all(result[j:j+2]==b'\3\10' for j in range(132,n-25,8)))
  if bool(flags&2)!=text_only:raise ValueError('Incorrect text-shape observation')
 else:
  if g!=UNKNOWN or baseline is not None or bn or pre or suf or any(packet[112:144]) or flags!=5 or n!=len(body):raise ValueError('Unknown raw structure')
  result=body
 if len(result)!=n or hashlib.sha256(result).digest()!=packet[144:176]:raise ValueError('Full reconstructed fingerprint')
 count=validate_forms(result)
 return result,{'kind':kind,'artifact_id':artifact,'package_index':index,'current_hii':f'{hii:016X}','package_list_guid':g,'bytes':n,'sha256':packet[144:176].hex(),'forms':count,'observed_instances':instances,'instance_index':instance_index,'cpu_text_only_shape':bool(flags&2),'content_unknown':kind==2,'authorization':False,'packet_sha256':hashlib.sha256(packet).hexdigest()}
