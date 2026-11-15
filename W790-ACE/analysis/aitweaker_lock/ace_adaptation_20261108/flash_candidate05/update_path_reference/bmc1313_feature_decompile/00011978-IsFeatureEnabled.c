
bool IsFeatureEnabled(undefined4 param_1)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  char *pcVar6;
  size_t __n;
  FILE *__stream;
  char *pcVar7;
  undefined4 local_42c;
  char local_428 [256];
  undefined4 local_328;
  undefined4 uStack_324;
  undefined4 uStack_320;
  undefined2 local_31c;
  undefined1 auStack_31a [241];
  char cStack_229;
  char local_228 [255];
  char cStack_129;
  char local_128 [260];
  
  piVar1 = DAT_00011bcc;
  local_328 = *DAT_00011bc8;
  uStack_324 = DAT_00011bc8[1];
  uStack_320 = DAT_00011bc8[2];
  local_31c = (undefined2)DAT_00011bc8[3];
  memset(auStack_31a,0,0xf2);
  if (*piVar1 == 0) {
    iVar5 = IniLoadFile(DAT_00011be4);
    *piVar1 = iVar5;
    if (iVar5 == 0) {
      return false;
    }
    __stream = fopen(DAT_00011bec,DAT_00011be8);
    uVar4 = DAT_00011bf4;
    uVar3 = DAT_00011bf0;
    uVar2 = DAT_00011bdc;
    if (__stream == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011bfc);
      return false;
    }
    while (iVar5 = feof(__stream), iVar5 == 0) {
      memset(local_428,0,0x100);
      __isoc99_fscanf(__stream,uVar3,local_428);
      if (local_428[0] != '\0' && local_428[0] != '#') {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar4,uVar2,0x294,local_428);
        local_42c = strchr(local_428,0x3d);
        if (local_42c == (char *)0x0) {
          iniparser_add_entry(*piVar1,&local_328,local_428,DAT_00011bf8);
        }
        else {
          memset(local_228,0,0x100);
          memset(local_128,0,0x100);
          pcVar6 = &cStack_229;
          pcVar7 = (char *)((int)&local_42c + 3);
          do {
            pcVar7 = pcVar7 + 1;
            if (*pcVar7 == '=') break;
            pcVar6 = pcVar6 + 1;
            *pcVar6 = *pcVar7;
          } while (pcVar7 != local_428 + 0xff);
          pcVar7 = &cStack_129;
          pcVar6 = local_42c;
          do {
            pcVar6 = pcVar6 + 1;
            if (*pcVar6 == '\0') break;
            pcVar7 = pcVar7 + 1;
            *pcVar7 = *pcVar6;
          } while (pcVar6 != local_42c + 0xff);
          iniparser_add_entry(*piVar1,&local_328,local_228,local_128);
        }
      }
    }
    fclose(__stream);
  }
  memset(local_428,0,0x100);
  iVar5 = snprintf(local_428,0x100,DAT_00011bd0,DAT_00011bc8,param_1);
  if (iVar5 < 0x100) {
    pcVar6 = (char *)iniparser_getstring(*piVar1,local_428,DAT_00011bd4);
    __n = strlen(pcVar6);
    iVar5 = strncmp(pcVar6,DAT_00011bd4,__n);
    return iVar5 != 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00011be0,DAT_00011bdc,DAT_00011bd8);
  return false;
}

