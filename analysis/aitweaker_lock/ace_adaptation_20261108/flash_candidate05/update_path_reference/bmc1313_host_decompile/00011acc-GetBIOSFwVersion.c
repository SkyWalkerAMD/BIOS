
undefined4 GetBIOSFwVersion(int param_1,void *param_2)

{
  int iVar1;
  char *__s;
  int iVar2;
  __off_t _Var3;
  size_t sVar4;
  int iVar5;
  char *pcVar6;
  size_t sVar7;
  size_t __size;
  int iVar8;
  char *__s1;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  
  local_3c = 0;
  local_40 = 0;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  __size = *(size_t *)(DAT_00011d64 + 0x1c);
  if (param_1 == 1) {
    iVar1 = get_bios_file_size(&local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011da8,DAT_00011d70,DAT_00011da4);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(DAT_00011d7c,2);
    if (iVar1 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d84,DAT_00011d70,DAT_00011d80);
      return 0xffffffff;
    }
  }
  else {
    if (param_1 != 2) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011d88,param_1);
      return 0xffffffff;
    }
    iVar1 = get_bios_spi_size(&local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d90,DAT_00011d70,DAT_00011d8c);
      return 0xffffffff;
    }
    iVar1 = find_bios_spi_device(&local_3c);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d98,DAT_00011d70,DAT_00011d94);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(&local_3c,2);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011da0,DAT_00011d70,DAT_00011d9c,&local_3c);
      return 0xffffffff;
    }
  }
  __s = malloc(__size);
  iVar2 = FUN_00011dac(local_40,__size);
  pcVar6 = DAT_00011d68;
  __s1 = __s;
  if (0 < iVar2) {
    iVar2 = 0;
    iVar8 = 0;
    do {
      memset(__s,0,__size);
      _Var3 = lseek(iVar1,iVar2,0);
      if (_Var3 == -1) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d74,DAT_00011d70,DAT_00011d6c,pcVar6);
        goto LAB_00011c00;
      }
      sVar4 = sigwrap_read(iVar1,__s,__size);
      if (__size != sVar4) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011d78,DAT_00011d70,0x238,pcVar6);
        goto LAB_00011c00;
      }
      if ((int)__size < 1) {
        sVar4 = 0;
      }
      else {
        sVar7 = 0;
        do {
          __s1 = __s + sVar7;
          iVar5 = strncmp(__s1,pcVar6,4);
          sVar7 = sVar7 + 1;
          if (iVar5 == 0) goto LAB_00011bf0;
          sVar4 = __size;
        } while (__size != sVar7);
      }
      iVar5 = FUN_00011dac(local_40,__size);
      iVar8 = iVar8 + 1;
      iVar2 = iVar2 + __size;
    } while (iVar8 < iVar5);
    __s1 = __s + sVar4;
  }
LAB_00011bf0:
  memcpy(param_2,__s1,0x80);
LAB_00011c00:
  free(__s);
  sigwrap_close(iVar1);
  return 0;
}

