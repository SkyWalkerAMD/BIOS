
int vmedia_cd_send_disk_eject_event(uint param_1)

{
  int iVar1;
  undefined1 auStack_20 [4];
  undefined1 local_1c;
  
  if (param_1 < 4) {
    local_1c = (undefined1)param_1;
    iVar1 = ioctl(*DAT_00027904,DAT_00027908,auStack_20);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00027910,DAT_0002790c,0xfa,param_1);
    iVar1 = -1;
  }
  return iVar1;
}

