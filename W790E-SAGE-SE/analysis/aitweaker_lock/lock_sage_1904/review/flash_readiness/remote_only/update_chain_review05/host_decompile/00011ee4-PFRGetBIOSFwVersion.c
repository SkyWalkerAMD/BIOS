
/* WARNING: Type propagation algorithm not settling */

undefined4 PFRGetBIOSFwVersion(int param_1,undefined4 param_2,int param_3)

{
  char *__s2;
  int iVar1;
  void *__ptr;
  char *__s1;
  int iVar2;
  uint uVar3;
  int iVar4;
  char *__size;
  __off_t __offset;
  char *pcVar5;
  uint local_5c;
  char *local_4c;
  char local_48 [12];
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  
  local_3c = 0;
  local_4c = (char *)0x0;
  local_48[0] = '\0';
  local_48[1] = '\0';
  local_48[2] = '\0';
  local_48[3] = '\0';
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_48[4] = '\0';
  local_48[5] = '\0';
  local_48[6] = '\0';
  local_48[7] = '\0';
  local_48[8] = '\0';
  local_48[9] = '\0';
  __size = *(char **)(DAT_00012230 + 0x1c);
  if (param_1 == 1) {
    iVar1 = get_bios_file_size(&local_4c);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012268,DAT_00012248,0x24c);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(DAT_00012240,2);
    if (iVar1 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001224c,DAT_00012248,DAT_00012244);
      return 0xffffffff;
    }
  }
  else {
    if (param_1 != 2) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00012250,param_1);
      return 0xffffffff;
    }
    iVar1 = get_bios_spi_size(&local_4c);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001225c,DAT_00012248,DAT_00012258);
      return 0xffffffff;
    }
    iVar1 = find_bios_spi_device(&local_3c);
    if (iVar1 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012254,DAT_00012248,0x260);
      return 0xffffffff;
    }
    iVar1 = sigwrap_open(&local_3c,2);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00012264,DAT_00012248,DAT_00012260,&local_3c);
      return 0xffffffff;
    }
  }
  if (param_3 == 1) {
    local_4c = (char *)0x1000000;
    __offset = 0;
  }
  else if ((param_3 == 0) || (param_3 == 2)) {
    __offset = 0x1000000;
    local_4c = (char *)0x1000000;
  }
  else {
    __offset = 0;
  }
  __ptr = malloc((size_t)__size);
  lseek(iVar1,__offset,0);
  __s2 = DAT_00012234;
  if (__size <= local_4c) {
    local_5c = 0;
    do {
      __offset = __offset + (int)__size;
      pcVar5 = (char *)0x0;
      sigwrap_read(iVar1,__ptr,__size);
      iVar4 = __offset + ~(uint)__size;
      while( true ) {
        __s1 = memchr((char *)((int)__ptr + (int)pcVar5),0x24,(int)__size - (int)pcVar5);
        if (__s1 == (char *)0x0) break;
        pcVar5 = __s1 + (1 - (int)__ptr);
        if (__s1 + (10 - (int)__ptr) < __size) {
          iVar2 = strncmp(__s1,__s2,9);
          if (iVar2 == 0) {
            printf(DAT_00012238,pcVar5 + iVar4,local_5c,pcVar5);
LAB_00012058:
            lseek(iVar1,(__off_t)(pcVar5 + iVar4),0);
            sigwrap_read(iVar1,param_2,0xd7);
            goto LAB_00012070;
          }
        }
        else {
          lseek(iVar1,(__off_t)(pcVar5 + iVar4),0);
          local_48[0] = '\0';
          local_48[1] = '\0';
          local_48[2] = '\0';
          local_48[3] = '\0';
          local_48[4] = '\0';
          local_48[5] = '\0';
          local_48[6] = '\0';
          local_48[7] = '\0';
          local_48[8] = '\0';
          local_48[9] = '\0';
          sigwrap_read(iVar1,local_48,9);
          iVar2 = strncmp(local_48,__s2,9);
          if (iVar2 == 0) {
            printf(DAT_0001223c,pcVar5 + iVar4,local_5c,pcVar5);
            goto LAB_00012058;
          }
          lseek(iVar1,__offset,0);
        }
      }
      uVar3 = FUN_0001226c(local_4c,__size);
      local_5c = local_5c + 1;
    } while (local_5c < uVar3);
  }
LAB_00012070:
  free(__ptr);
  sigwrap_close(iVar1);
  return 0;
}

