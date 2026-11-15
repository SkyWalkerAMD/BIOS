
undefined4 FUN_000191f0(char *param_1)

{
  FILE *__s;
  int iVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  uint uVar5;
  byte local_19;
  
  iVar2 = 0;
  local_19 = 0;
  FUN_00018ccc(&local_19);
  pcVar4 = DAT_00019378;
  if (3 < local_19) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000193a0,DAT_0001939c,DAT_00019398,param_1);
    return 0xffffffff;
  }
  __s = fopen(DAT_00019378,DAT_0001937c);
  if (__s == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000193a4,DAT_0001939c,0x370,pcVar4);
    return 0xffffffff;
  }
  uVar5 = (uint)local_19;
  pcVar4 = DAT_00019380;
  if (uVar5 != 0) {
    do {
      iVar1 = strcmp(param_1,pcVar4);
      iVar2 = iVar2 + 1;
      if (iVar1 == 0) {
        *pcVar4 = '\0';
      }
      pcVar4 = pcVar4 + 0x14;
    } while (iVar2 < (int)uVar5);
    if (uVar5 != 0) {
      fwrite(DAT_00019388,1,0xe,__s);
      pcVar4 = DAT_0001938c;
      uVar5 = (uint)local_19;
      if (uVar5 != 0) {
        iVar2 = 0;
        pcVar3 = DAT_00019380;
        do {
          iVar2 = iVar2 + 1;
          if (*pcVar3 != '\0') {
            fprintf(__s,pcVar4,pcVar3);
            uVar5 = (uint)local_19;
          }
          pcVar3 = pcVar3 + 0x14;
        } while (iVar2 < (int)uVar5);
      }
      fwrite(DAT_00019390,1,2,__s);
      local_19 = local_19 - 1;
      uVar5 = (uint)local_19;
      goto LAB_00019270;
    }
  }
  uVar5 = 0;
LAB_00019270:
  fprintf(__s,DAT_00019384,uVar5);
  fclose(__s);
  if (local_19 != 0) {
    return 0;
  }
  safe_system(DAT_00019394);
  return 0;
}

