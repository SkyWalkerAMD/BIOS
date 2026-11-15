
/* WARNING: Type propagation algorithm not settling */

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
  int __offset;
  char *__s1;
  int local_40 [7];
  
  local_40[1] = 0;
  local_40[0] = 0;
  local_40[2] = 0;
  local_40[3] = 0;
  local_40[4] = 0;
  local_40[5] = 0;
  __size = *(size_t *)(DAT_00011e98 + 0x1c);
  if (param_1 == 1) {
    iVar1 = get_bios_file_size(local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ee0,DAT_00011ea4,DAT_00011edc);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(DAT_00011eb4,2);
    if (iVar1 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ebc,DAT_00011ea4,DAT_00011eb8);
      return 0xffffffff;
    }
  }
  else {
    if (param_1 != 2) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ec0,param_1);
      return 0xffffffff;
    }
    iVar1 = get_bios_spi_size(local_40);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ec8,DAT_00011ea4,DAT_00011ec4);
      return 0xffffffff;
    }
    iVar1 = find_bios_spi_device(local_40 + 1);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ed0,DAT_00011ea4,DAT_00011ecc);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(local_40 + 1,2);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ed8,DAT_00011ea4,DAT_00011ed4,local_40 + 1);
      return 0xffffffff;
    }
  }
  if (local_40[0] == 0x4000000) {
    __offset = 0x3000000;
    local_40[0] = 0x1000000;
  }
  else {
    __offset = 0;
  }
  iVar2 = local_40[0];
  __s = malloc(__size);
  iVar2 = FUN_0001226c(iVar2,__size);
  pcVar6 = DAT_00011e9c;
  __s1 = __s;
  if (0 < iVar2) {
    iVar2 = 0;
    do {
      memset(__s,0,__size);
      _Var3 = lseek(iVar1,__offset,0);
      if (_Var3 == -1) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011ea8,DAT_00011ea4,DAT_00011ea0,pcVar6);
        goto LAB_00011d34;
      }
      sVar4 = sigwrap_read(iVar1,__s,__size);
      if (__size != sVar4) {
        pcVar6 = strerror(0);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011eb0,DAT_00011ea4,DAT_00011eac,pcVar6);
        goto LAB_00011d34;
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
          if (iVar5 == 0) goto LAB_00011d24;
          sVar4 = __size;
        } while (__size != sVar7);
      }
      iVar5 = FUN_0001226c(local_40[0],__size);
      iVar2 = iVar2 + 1;
      __offset = __offset + __size;
    } while (iVar2 < iVar5);
    __s1 = __s + sVar4;
  }
LAB_00011d24:
  memcpy(param_2,__s1,0x80);
LAB_00011d34:
  free(__s);
  sigwrap_close(iVar1);
  return 0;
}

