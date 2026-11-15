
undefined4 get_bios_spi_size(int *param_1)

{
  char *__needle;
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  char cStack_68;
  byte abStack_67 [79];
  
  pcVar1 = DAT_00011094;
  memset(&cStack_68,0,0x50);
  __stream = fopen(pcVar1,DAT_00011098);
  __needle = DAT_0001109c;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000110a4,DAT_000110a0,0x4c,pcVar1);
    uVar3 = 0xffffffff;
  }
  else {
    iVar6 = 1;
    while (pcVar1 = fgets(&cStack_68,0x50,__stream), pcVar1 != (char *)0x0) {
      pcVar1 = strstr(&cStack_68,__needle);
      if (pcVar1 != (char *)0x0) {
        iVar2 = *param_1;
        if (abStack_67[3] == ':') {
          iVar7 = 0xd;
        }
        else {
          iVar7 = 0xe;
        }
        pbVar4 = abStack_67 + iVar7;
        do {
          pbVar4 = pbVar4 + -1;
          iVar5 = *pbVar4 - 0x30;
          if (9 < iVar5) {
            iVar5 = *pbVar4 - 0x57;
          }
          iVar2 = iVar6 * iVar5 + iVar2;
          iVar6 = iVar6 << 4;
        } while (pbVar4 != abStack_67 + iVar7 + -8);
        *param_1 = iVar2;
      }
    }
    fclose(__stream);
    uVar3 = 0;
  }
  return uVar3;
}

