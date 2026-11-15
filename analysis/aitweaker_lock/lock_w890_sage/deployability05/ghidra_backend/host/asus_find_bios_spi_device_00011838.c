
undefined4 asus_find_bios_spi_device(char *param_1)

{
  FILE *__stream;
  size_t sVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  undefined4 uVar6;
  char *__delim;
  undefined4 local_78;
  char acStack_74 [80];
  int local_24;
  
  local_24 = **(int **)(DAT_00011a00 + 0x1184c + DAT_00011a04);
  local_78 = 0;
  if (param_1 == (char *)0x0) {
    iVar4 = DAT_00011a0c + 0x11884;
    pcVar5 = (char *)(DAT_00011a08 + 0x1188e);
    iVar3 = DAT_00011a10 + 0x1188c;
    uVar6 = 0x14f;
  }
  else {
    pcVar5 = (char *)(DAT_00011a18 + 0x118d4);
    __stream = fopen(pcVar5,(char *)(DAT_00011a1c + 0x118d8));
    if (__stream != (FILE *)0x0) {
      iVar3 = -1;
      pcVar5 = (char *)(DAT_00011a38 + 0x119d0);
      __delim = (char *)(DAT_00011a3c + 0x119d4);
      while( true ) {
        do {
          pcVar2 = fgets(acStack_74,0x50,__stream);
          if (pcVar2 == (char *)0x0) {
            fclose(__stream);
            if (iVar3 == -1) {
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00011a34 + 0x119b8,DAT_00011a30 + 0x119b4,0x16e);
              uVar6 = 0xffffffff;
            }
            else {
              snprintf(param_1,0x20,(char *)(DAT_00011a40 + 0x119ec),iVar3);
              uVar6 = 0;
            }
            goto LAB_0001189c;
          }
          pcVar2 = strstr(acStack_74,pcVar5);
        } while (pcVar2 == (char *)0x0);
        pcVar2 = strtok(acStack_74,__delim);
        if (pcVar2 == (char *)0x0) break;
        sVar1 = strlen(pcVar2);
        pcVar2 = memcpy(&local_78,pcVar2 + 3,sVar1 - 3);
        iVar3 = atoi(pcVar2);
      }
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011a2c + 0x11944,DAT_00011a28 + 72000,0x161);
      fclose(__stream);
      goto LAB_00011898;
    }
    uVar6 = 0x156;
    iVar4 = DAT_00011a20 + 0x118f8;
    iVar3 = DAT_00011a24 + 0x11900;
  }
  IDBG_LINUXAPP_DbgOut(0x82,iVar3,iVar4,uVar6,pcVar5);
LAB_00011898:
  uVar6 = 0xffffffff;
LAB_0001189c:
  if (local_24 != **(int **)(DAT_00011a14 + 0x118ac + DAT_00011a04)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar6;
}

