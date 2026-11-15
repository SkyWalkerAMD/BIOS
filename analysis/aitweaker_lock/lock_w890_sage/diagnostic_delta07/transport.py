"""Budgeted ASCII envelope inside unchanged P3 CRC/QR transport.
Caller must supply an independently accepted selection; QR data is not authority.
No default deployment budget is assigned here.
"""
import base64,hashlib,re,struct,zlib,importlib.util
from pathlib import Path
from decode_packet import decode,baseline_for
PREFIX=b'AITWEAKER-PROBE-P3-KVM\r\nW890_DELTA07_DIAGNOSTIC_ONLY\r\n'
FOOT=b'COLLECTION_STATUS=PARTIAL\r\nPROBE_COMPLETE\r\n'
HEAD=re.compile(rb'D7 SOURCE=([0-9a-f]{64}) SELECTION=([0-9a-f]{64}) PLANNED=([0-9]{1,4})\r\n')
OBJ=re.compile(rb'D7 OBJ=([0-9A-F]{8}) N=([0-9]{1,8}) SHA=([0-9a-f]{64}) (PRESENT|OMITTED_BUDGET|REFUSED)\r\n')
OBS=re.compile(rb'D7 OBS=([0-9A-F]{8}) H=([0-9A-F]{16}) I=([0-9A-F]{16}) B=([0-9A-F]{16}) L=([0-9]{1,8}) S=([0-9a-f]{64}) C=([A-Z_]{1,40}) R=([0-9a-f]{64}|-) N=([0-9a-f]{64}|-)\r\n')
ENV=re.compile(rb'D7 ENV ISSUES=([0-9]{1,8}) MAP=(READY|REFUSED) TSE_COUNT=([0-9]{1,4})\r\n')
SPF=re.compile(rb'D7 SPF A=([0-9A-F]{140}) B=([0-9A-F]{140}) CRC=([0-9A-F]{8}) SHA=([0-9a-f]{64}) E=(MODULE_UNAVAILABLE|MAP_UNAVAILABLE|MODULE_CHANGED|COMPLETE_OBSERVATION|INCOMPLETE_OBSERVATION)\r\n')
END=re.compile(rb'D7 EXPORTED=([0-9]{1,4}) PLANNED=([0-9]{1,4}) STATUS=(COMPLETE|PARTIAL)\r\n')
def selected_ids(targets):
 ids={}
 for target in targets:
  for i in range(target['expected_instances']):
   n=target['artifact_base']+i
   if n in ids or not 1<=n<=0xffffffff:raise ValueError('Selection artifact overlap/range')
   ids[n]=target
 if not ids or len(ids)>4096:raise ValueError('Selection count')
 return ids
def render(packets,targets,source,selection,budget_bytes,baseline=None):
 if not 1<=budget_bytes<=65536 or len(source)!=32 or len(selection)!=32:raise ValueError('Explicit transport budget/identity required')
 ids=selected_ids(targets);present={};headers={};bodies={}
 for packet in packets:
  if len(packet)<224:raise ValueError('Short packet')
  n=struct.unpack_from('<I',packet,16)[0]
  if n in present or n not in ids or packet[48:80]!=source or packet[80:112]!=selection:raise ValueError('Packet/selection mismatch')
  decode(packet,baseline_for(ids[n],baseline),source,selection,len(packet),ids[n])
  present[n]=packet;head=f'D7 OBJ={n:08X} N={len(packet)} SHA={hashlib.sha256(packet).hexdigest()} '.encode();headers[n]=head
  b64=base64.b64encode(packet);bodies[n]=b''.join(b'D7+ '+b64[i:i+96]+b'\r\n' for i in range(0,len(b64),96))
 if present.keys()!=ids.keys():raise ValueError('Missing selection before transport; caller must emit separate diagnostic-only failure, not incomplete objects')
 head=PREFIX+f'D7 SOURCE={source.hex()} SELECTION={selection.hex()} PLANNED={len(ids)}\r\n'.encode()
 def tail(n):return f'D7 EXPORTED={n} PLANNED={len(ids)} STATUS={"COMPLETE" if n==len(ids) else "PARTIAL"}\r\n'.encode()+FOOT
 chosen=set();chunks={n:headers[n]+b'OMITTED_BUDGET\r\n' for n in ids}
 def encoded():return head+b''.join(chunks[n] for n in sorted(ids))+tail(len(chosen))
 if len(encoded())>budget_bytes:raise ValueError('Budget cannot hold complete omission manifest')
 required=len(head)+sum(len(headers[n]+b'PRESENT\r\n'+bodies[n]) for n in ids)+len(tail(len(ids)))
 for n in sorted(ids):
  old=chunks[n];chunks[n]=headers[n]+b'PRESENT\r\n'+bodies[n];chosen.add(n)
  if len(encoded())>budget_bytes:chosen.remove(n);chunks[n]=old
 result=encoded();assert len(result)<=budget_bytes
 return result,{'bytes':len(result),'pages_at_768':(len(result)+767)//768,'selected_objects':len(ids),'exported_objects':len(chosen),'omitted_ids':sorted(ids.keys()-chosen),'full_required_bytes':required,'complete':len(chosen)==len(ids),'explicit_budget_bytes':budget_bytes}
def parse(log,targets,source,selection,baseline,capacity):
 if len(log)>capacity or len(log)>65536 or not log.startswith(PREFIX) or not log.endswith(FOOT):raise ValueError('Envelope extent/version')
 pos=len(PREFIX);head=HEAD.match(log,pos)
 if not head or bytes.fromhex(head[1].decode())!=source or bytes.fromhex(head[2].decode())!=selection:raise ValueError('Envelope collection binding')
 ids=selected_ids(targets)
 if int(head[3])!=len(ids):raise ValueError('Envelope selection count')
 pos=head.end();objects={};identities=set();omitted=[];refused=[];observations={};environment=None;spf=None
 if log.startswith(b'D7 ENV ',pos):
  e=ENV.match(log,pos)
  if not e:raise ValueError('Environment observation')
  environment={'issues':int(e[1]),'map':e[2].decode(),'tse_count':int(e[3])};pos=e.end()
  record=SPF.match(log,pos)
  if not record:raise ValueError('Missing complete SPF observation pair')
  raw=bytes.fromhex((record[1]+record[2]).decode())
  if zlib.crc32(raw)!=int(record[3],16) or hashlib.sha256(raw).hexdigest().encode()!=record[4]:raise ValueError('SPF pair CRC/SHA')
  path=Path(__file__).resolve().parent.parent/'spf_sampler06/decode.py';spec=importlib.util.spec_from_file_location('d7_spf_decoder',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  spf=module.decode_pair(raw[:70],raw[70:]);spf['carrier_state']=record[5].decode()
  state=spf['carrier_state'];masks=(spf['a']['status_mask'],spf['b']['status_mask'])
  complete=spf['observations_equal'] and spf['both_reads_complete'] and all((mask&0x1ffff)==0x1ffff and not mask&0xf80000 for mask in masks)
  if state in ('COMPLETE_OBSERVATION','INCOMPLETE_OBSERVATION'):
   if environment['map']!='READY' or environment['tse_count']!=1 or (state=='COMPLETE_OBSERVATION')!=complete:raise ValueError('SPF carrier completeness/identity mismatch')
  else:
   if masks!=(module.PROFILE,module.PROFILE):raise ValueError('Unavailable SPF pair contains actual fields')
   if state=='MAP_UNAVAILABLE' and (environment['map']!='REFUSED' or environment['tse_count']):raise ValueError('SPF unavailable map contradiction')
   if state=='MODULE_UNAVAILABLE' and (environment['map']!='READY' or environment['tse_count']==1):raise ValueError('SPF unavailable module contradiction')
   if state=='MODULE_CHANGED' and (environment['map']!='READY' or environment['tse_count']!=1):raise ValueError('SPF changed module contradiction')
  pos=record.end()
 while log.startswith((b'D7 OBJ=',b'D7 OBS='),pos):
  observation=None
  if log.startswith(b'D7 OBS=',pos):
   ob=OBS.match(log,pos)
   if not ob:raise ValueError('Object observation')
   oid=int(ob[1],16)
   if oid not in ids or oid in observations:raise ValueError('Observation identity')
   observation={'hii':ob[2].decode(),'producer':ob[3].decode(),'base':ob[4].decode(),'bytes':int(ob[5]),'sha256':ob[6].decode(),'status':ob[7].decode(),'raw_sha':ob[8].decode(),'normalized_sha':ob[9].decode()};observations[oid]=observation;pos=ob.end()
  match=OBJ.match(log,pos)
  if not match:raise ValueError('Object header')
  n=int(match[1],16);length=int(match[2]);sha=match[3].decode();mode=match[4];pos=match.end()
  if n not in ids or n in objects or n in omitted or n in refused or (observation is not None and oid!=n):raise ValueError('Object bounds/duplicate')
  if mode==b'REFUSED':
   if length or sha!='0'*64 or observation is None or observation['status'] in ('ORIGINAL_CODE_MATCH','UNKNOWN_OBSERVED'):raise ValueError('Refusal mismatch')
   refused.append(n);continue
  if length<224 or length>ids[n]['result_bytes']+224:raise ValueError('Object extent')
  if observation is not None:
   wanted='UNKNOWN_OBSERVED' if ids[n]['kind']==2 else 'ORIGINAL_CODE_MATCH'
   if observation['status']!=wanted or observation['bytes']!=ids[n]['result_bytes'] or observation['sha256']!=ids[n]['result_sha256']:raise ValueError('Observation selection mismatch')
  if mode==b'OMITTED_BUDGET':omitted.append(n);continue
  if length>capacity:raise ValueError('Present object exceeds budget')
  blocks=[]
  while log.startswith(b'D7+ ',pos):
   end=log.find(b'\r\n',pos)
   if end<0:raise ValueError('Missing data line end')
   block=log[pos+4:end]
   if not 1<=len(block)<=96 or len(block)%4:raise ValueError('Base64 line width')
   blocks.append(block);pos=end+2
  try:packet=base64.b64decode(b''.join(blocks),validate=True)
  except Exception as error:raise ValueError('Invalid Base64') from error
  if len(packet)!=length or hashlib.sha256(packet).hexdigest()!=sha:raise ValueError('Full packet hash/length')
  target=ids[n];data,meta=decode(packet,baseline_for(target,baseline),source,selection,capacity,target)
  if observation is not None and observation['hii']!=meta['current_hii']:raise ValueError('Observed/current HII mismatch')
  key=(meta['current_hii'],meta['package_index'])
  if key in identities:raise ValueError('Repeated current HII package identity')
  identities.add(key);objects[n]={'metadata':meta,'forms':data}
 end=END.match(log,pos)
 if not end or end.end()+len(FOOT)!=len(log) or log[end.end():]!=FOOT:raise ValueError('Complete envelope footer')
 if int(end[1])!=len(objects) or int(end[2])!=len(ids) or objects.keys()|set(omitted)|set(refused)!=ids.keys() or (end[3]==b'COMPLETE')!=(not omitted and not refused):raise ValueError('Envelope completeness mismatch')
 if environment is not None and observations.keys()!=ids.keys():raise ValueError('Incomplete observations')
 nonzero_hii=[ob['hii'] for ob in observations.values() if int(ob['hii'],16)]
 if len(nonzero_hii)!=len(set(nonzero_hii)):raise ValueError('Duplicate current HII observations')
 return {'objects':objects,'omitted':omitted,'refused':refused,'observations':observations,'environment':environment,'spf':spf,'complete':not omitted and not refused,'authorization':False,'log_sha256':hashlib.sha256(log).hexdigest()}
