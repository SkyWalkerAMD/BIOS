"""Limited actual-463b notice UI integration with explicit console/GOP doubles."""
import importlib.util
import json
import struct
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('unified_notice_fixture',HERE/'verify_unified_efi.py')
unified=importlib.util.module_from_spec(spec);spec.loader.exec_module(unified)
b=unified.b
U=b.x86
GOP=uuid.UUID('9042a9de-23dc-4a38-96fb-7aded080516a').bytes_le


class NoticeFixture(unified.UnifiedFixture):
 def __init__(self):
  self.ui_enabled=False;self.ui_events=[];self.messages=[];self.retired_ui=False
  self.ack_retire=False;self.ack_error=False;self.not_ready=0;self.retire_frame=None
  super().__init__()
  self.attempt('CommonSave',True)  # real guard -> marker -> owned notice
  self.out=b.ARENA+0x5000;self.input=b.ARENA+0x5100;self.mode=b.ARENA+0x5200
  self.gop=b.ARENA+0x5300;self.gmode=b.ARENA+0x5400;self.info=b.ARENA+0x5500
  self.q(self.st+48,self.input);self.q(self.st+64,self.out)
  self.q(self.input+8,b.STOP+0x250)
  for offset,stub in ((8,0x200),(40,0x210),(48,0x220),(56,0x230),(64,0x240)):
   self.q(self.out+offset,b.STOP+stub)
  self.q(self.out+72,self.mode)
  self.mode_before=struct.pack('<iiiiiB3x',1,0,7,4,2,0)
  self.uc.mem_write(self.mode,self.mode_before)
  self.q(self.gop+16,b.STOP+0x260);self.q(self.gop+24,self.gmode)
  self.uc.mem_write(self.gmode,struct.pack('<IIQQQQ',1,0,self.info,36,0,0))
  self.uc.mem_write(self.info,struct.pack('<IIIIIIIII',0,4,3,0,0,0,0,0,4))
  self.q(self.bs+0xf8,b.STOP+0x270)
  self.uc.mem_write(b.STOP+0x200,b'\xc3'*0x100)
  self.framebuffer=bytes(range(48));self.framebuffer_before=self.framebuffer
  self.ui_enabled=True

 def utf16(self,address):
  out=bytearray()
  for index in range(2048):
   unit=bytes(self.uc.mem_read(address+index*2,2))
   if unit==b'\0\0':return out.decode('utf-16-le')
   out.extend(unit)
  raise AssertionError('unbounded console string')

 def hook(self,uc,address,size,data):
  if self.ui_enabled:
   if address==b.STOP+0x280:  # continuation after actual end_platform call
    old_rsp,key_pointer=self.retire_frame
    uc.reg_write(U.UC_X86_REG_RSP,old_rsp)
    uc.mem_write(key_pointer,struct.pack('<HH',0,13))
    self.return_service(unified.state.ERR(6) if self.ack_error else 0)
    return
   service=(address-b.STOP) in self.service_map or 0x200<=address-b.STOP<=0x270
   if self.retired_ui and service:
    raise AssertionError('console/GOP/pool/Stall service used after ack retirement')
   rcx,rdx,r8,r9=[uc.reg_read(reg) for reg in (U.UC_X86_REG_RCX,U.UC_X86_REG_RDX,U.UC_X86_REG_R8,U.UC_X86_REG_R9)]
   if address==b.STOP+0x170 and bytes(uc.mem_read(rcx,16))==GOP:
    self.ui_events.append('LocateGOP');self.q(r8,self.gop);self.return_service(0);return
   if address==b.STOP+0x110:self.ui_events.append('AllocatePool')
   if address==b.STOP+0x120:self.ui_events.append('FreePool')
   if address==b.STOP+0x200:
    text=self.utf16(rdx);self.messages.append(text);self.ui_events.append('OutputString')
    self.framebuffer=bytes([0xee])*48;self.return_service(0);return
   if address==b.STOP+0x210:
    self.ui_events.append('SetAttribute');uc.mem_write(self.mode+8,struct.pack('<I',rdx));self.return_service(0);return
   if address==b.STOP+0x220:
    self.ui_events.append('ClearScreen');self.framebuffer=bytes(48);self.return_service(0);return
   if address==b.STOP+0x230:
    self.ui_events.append('SetCursorPosition');uc.mem_write(self.mode+12,struct.pack('<II',rdx,r8));self.return_service(0);return
   if address==b.STOP+0x240:
    self.ui_events.append('EnableCursor');uc.mem_write(self.mode+20,bytes([rdx&255]));self.return_service(0);return
   if address==b.STOP+0x260:
    rsp=uc.reg_read(U.UC_X86_REG_RSP)
    width,height=self.readq(rsp+0x40),self.readq(rsp+0x48)
    assert width==4 and height==3
    if r8==1:
     self.ui_events.append('GOP_VIDEO_TO_BUFFER');uc.mem_write(rdx,self.framebuffer)
    elif r8==2:
     self.ui_events.append('GOP_BUFFER_TO_VIDEO');self.framebuffer=bytes(uc.mem_read(rdx,48))
    else:raise AssertionError('unexpected BLT operation')
    self.return_service(0);return
   if address==b.STOP+0x270:
    self.ui_events.append('Stall');assert rcx==1000;self.return_service(0);return
   if address==b.STOP+0x250:
    self.ui_events.append('ReadKey')
    if self.ack_retire:
     self.ack_retire=False;self.retired_ui=True;self.ui_events.append('RETIRE_BEGIN')
     self.d(self.sym('boot_services_ended','services.obj'),1)
     old_rsp=uc.reg_read(U.UC_X86_REG_RSP);self.retire_frame=(old_rsp,rdx)
     # Call the actual end_platform with proper x64 home area and return to a
     # local input-service continuation, then resume the actual key/show code.
     self.q(old_rsp-0x30,b.STOP+0x280)
     uc.reg_write(U.UC_X86_REG_RSP,old_rsp-0x30)
     uc.reg_write(U.UC_X86_REG_RIP,self.sym('end_platform','platform.obj'))
     return
    if self.not_ready:
     self.not_ready-=1;self.return_service(unified.state.ERR(6));return
    uc.mem_write(rdx,struct.pack('<HH',0,13));self.return_service(unified.state.ERR(7) if self.ack_error else 0);return
  super().hook(uc,address,size,data)

 def show(self):
  self.call(self.sym('show_save_notice','ui.obj'),[0,0,0,0])
  return {'text':''.join(self.messages),'events':self.ui_events.copy(),
   'notice_pending':hex(self.get_actual('notice_status')),
   'ui_busy':self.get_actual('ui_busy',4,'ui.obj'),
   'framebuffer_restored':self.framebuffer==self.framebuffer_before,
   'text_mode_restored':bytes(self.uc.mem_read(self.mode,24))==self.mode_before,
   'retired':bool(self.get_actual('retired',4)),
   'actual_owner':self.call(self.sym('platform_session_owned','platform.obj'),[0,0,0,0])}


def main():
 rows=[]
 for status in (b.DENIED,unified.state.ERR(7)):
  f=NoticeFixture()
  if status!=b.DENIED:f.q(f.sym('notice_status'),status)
  row=f.show()
  assert 'Other settings may already have been saved.' in row['text']
  expected=('A protected change was rejected. Unlock Ai Tweaker before retrying.' if status==b.DENIED else
            'Save state could not be verified. Ai Tweaker remains locked.')
  assert expected in row['text']
  assert row['framebuffer_restored'] and row['text_mode_restored'] and row['ui_busy']==0
  assert row['events'].count('GOP_VIDEO_TO_BUFFER')==row['events'].count('GOP_BUFFER_TO_VIDEO')==row['events'].count('FreePool')==1
  event_count=len(f.ui_events);f.show();assert len(f.ui_events)==event_count
  rows.append({'case':'notice_text_screen_and_once','status':hex(status),
   'producer':'actual guard-denied save' if status==b.DENIED else 'ERR7 status field fixture after actual guard-denied save',
   'result':row,'second_call_no_services':True})
 for busy in ('ui','core'):
  f=NoticeFixture()
  if busy=='ui':f.d(f.sym('ui_busy','ui.obj'),1)
  else:f.uc.mem_write(f.sym('password_core','services.obj')+202,b'\x01')
  first=f.show();assert not first['events'] and first['notice_pending']==hex(b.DENIED)
  if busy=='ui':f.d(f.sym('ui_busy','ui.obj'),0)
  else:f.uc.mem_write(f.sym('password_core','services.obj')+202,b'\0')
  second=f.show();assert second['framebuffer_restored'] and second['notice_pending']=='0x0'
  rows.append({'case':busy+'_busy_defers_without_consuming','deferred':first,'eventual':second})
 f=NoticeFixture();f.d(f.sym('loop_depth','platform.obj'),0);r=f.show()
 assert not r['events'] and r['notice_pending']==hex(b.DENIED)
 f.set_owner(2,True,False);r2=f.show();assert not r2['events'] and r2['notice_pending']=='0x0'
 rows.append({'case':'no_owner_then_new_token_never_displays_stale_notice','unowned':r,'new_session':r2})
 f=NoticeFixture();f.set_owner(2,True,False);r=f.show();assert not r['events'] and r['notice_pending']=='0x0'
 rows.append({'case':'stale_token_suppressed_by_actual_take_notice','result':r})
 for missing in ('input','output'):
  f=NoticeFixture();offset=48 if missing=='input' else 64;value=f.readq(f.st+offset);f.q(f.st+offset,0)
  first=f.show();assert not first['events'] and first['notice_pending']==hex(b.DENIED)
  f.q(f.st+offset,value);second=f.show();assert second['framebuffer_restored'] and second['notice_pending']=='0x0'
  rows.append({'case':'missing_'+missing+'_does_not_consume_notice','deferred':first,'eventual':second})
 f=NoticeFixture();f.not_ready=1;r=f.show()
 assert r['events'].count('ReadKey')==2 and r['events'].count('Stall')==1 and r['framebuffer_restored']
 rows.append({'case':'ack_not_ready_then_key','result':r})
 f=NoticeFixture();f.ack_error=True;r=f.show();assert r['framebuffer_restored'] and r['text_mode_restored']
 rows.append({'case':'ack_device_error_still_restores_screen','result':r})
 for error in (False,True):
  f=NoticeFixture();f.ack_retire=True;f.ack_error=error;r=f.show()
  assert r['retired'] and r['actual_owner']==0 and r['ui_busy']==0 and r['notice_pending']=='0x0'
  assert r['events'][-1]=='RETIRE_BEGIN'
  assert 'GOP_BUFFER_TO_VIDEO' not in r['events'] and 'FreePool' not in r['events'] and 'Stall' not in r['events']
  rows.append({'case':'ack_retires_then_'+('NOT_READY' if error else 'success'),'result':r,
   'post_retirement_service_calls':0,'captured_pixels_intentionally_not_freed_after_retirement':True})
 report={'status':'PASS_UNIFIED_463B_ACTUAL_NOTICE_UI_WITH_GOP_CONSOLE_FIXTURES','cases':len(rows),'rows':rows,
  'efi_sha256':unified.PIN,'script_sha256':b.sha(Path(__file__).read_bytes()),
  'actual_code':['show_save_notice','save_feedback_take_notice','platform_session_owned','save_screen','restore_screen','acknowledge','key','end_platform','save_feedback_retire','audit'],
  'fixtures':['4x3 GOP framebuffer snapshot/restore','console output/mode/keyboard services','one NOT_READY stall cycle','boot retirement during input callback'],
  'production_changes':False,'production_rebuild':False,'device_access':False,
  'limits':['This tests service calls, content, saved pixel bytes and mode restoration, not physical BMC/GOP rendering or human readability.',
   'ERR7 selects the generic notice branch with an explicitly identified notification-state fixture; ERR15 is produced by actual guard denial.',
   'Retirement is injected during acknowledgement as requested; arbitrary firmware retirement at every earlier graphics service boundary is not covered.']}
 out=HERE/'notice_ui_verification.json';out.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'status':report['status'],'cases':len(rows),'output':str(out),'sha256':b.sha(out.read_bytes())},indent=2))


if __name__=='__main__':main()
