
undefined4 ActiveHostSPIDriver(int param_1)

{
  FILE *__stream;
  byte local_91;
  undefined4 local_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  undefined4 uStack_84;
  undefined4 local_80;
  undefined4 uStack_7c;
  undefined4 uStack_78;
  undefined2 local_74;
  
  memset(&local_90,0,0x80);
  local_91 = 0;
  __stream = fopen(DAT_00013374,DAT_00013370);
  if (__stream != (FILE *)0x0) {
    fread(&local_91,1,1,__stream);
    fclose(__stream);
  }
  if (local_91 != 0) {
    local_91 = local_91 - 0x30;
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013378,param_1);
  if (param_1 == 0) {
    SwitchGPIO(0);
    sleep(1);
    snprintf((char *)&local_90,0x80,DAT_0001337c,(uint)local_91);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013388,DAT_00013384,0xd6,DAT_00013380,&local_90);
    safe_system(&local_90);
    return 0;
  }
  local_90 = *DAT_0001338c;
  uStack_8c = DAT_0001338c[1];
  uStack_88 = DAT_0001338c[2];
  uStack_84 = DAT_0001338c[3];
  local_80 = DAT_0001338c[4];
  uStack_7c = DAT_0001338c[5];
  uStack_78 = DAT_0001338c[6];
  local_74 = (undefined2)DAT_0001338c[7];
  safe_system(&local_90);
  SwitchGPIO(1);
  ClearASUSBiosHeader();
  return 0;
}

