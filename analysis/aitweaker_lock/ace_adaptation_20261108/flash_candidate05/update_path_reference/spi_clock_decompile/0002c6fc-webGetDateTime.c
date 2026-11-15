
int webGetDateTime(undefined4 param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 uVar2;
  size_t sVar3;
  undefined4 uVar4;
  uint3 local_dc;
  undefined1 uStack_d9;
  uint local_d8;
  byte local_d4;
  undefined1 auStack_d0 [64];
  char acStack_90 [128];
  
  memset(acStack_90,0,0x80);
  iVar1 = IPMICMD_GetSELTime(param_1,&local_d8,0x1e);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0002c924,DAT_0002c8f8,DAT_0002c920,iVar1);
    return iVar1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut
            (0x87,DAT_0002c900,DAT_0002c8f8,DAT_0002c8fc,(uint)local_d4 << 0x18 | local_d8 >> 8);
  iVar1 = IPMICMD_GetSELTimeUTCOffset(param_1,&local_dc,0x1e);
  if (iVar1 == 0) {
    iVar1 = (_local_dc << 8) >> 0x10;
    if (iVar1 == DAT_0002c904) {
      local_dc = (uint3)(byte)local_dc;
      iVar1 = 0;
    }
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c908,DAT_0002c8f8,DAT_0002c90c,iVar1);
    if (*(int *)(DAT_0002c910 + 0x140) == 1) {
      memset(auStack_d0,0,0x40);
      iVar1 = LIBIPMI_HL_AMIGetTimeZone(param_1,auStack_d0,0x1e);
      if (iVar1 != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c93c,DAT_0002c8f8,DAT_0002c938,iVar1);
        return iVar1;
      }
      Escaper(auStack_d0,acStack_90);
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0002c92c,DAT_0002c8f8,DAT_0002c928,acStack_90);
    }
    uVar4 = *param_2;
    uVar2 = json_object_new_int((uint)local_d4 << 0x18 | local_d8 >> 8);
    json_object_object_add(uVar4,DAT_0002c914,uVar2);
    uVar4 = *param_2;
    uVar2 = json_object_new_int((_local_dc << 8) >> 0x10);
    json_object_object_add(uVar4,DAT_0002c918,uVar2);
    sVar3 = strlen(acStack_90);
    uVar4 = *param_2;
    uVar2 = json_object_new_string_len(acStack_90,sVar3);
    json_object_object_add(uVar4,DAT_0002c91c,uVar2);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_0002c934,DAT_0002c8f8,DAT_0002c930,iVar1);
  return iVar1;
}

