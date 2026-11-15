
ulonglong FUN_180003700(char *param_1,LPCSTR param_2,undefined8 param_3,undefined8 param_4)

{
  char cVar1;
  ulonglong uVar2;
  int iVar3;
  char *pcVar4;
  
  iVar3 = -1;
  if (param_2[0x121] == '\x01') {
    FUN_180004400("CloseHarddiskImage is not called for previous image file\n",param_2,param_1,
                  param_4);
    return 0xfffffff4;
  }
  uVar2 = 0xffffffffffffffff;
  param_2[0x121] = '\0';
  param_2[0x110] = -1;
  param_2[0x111] = -1;
  param_2[0x112] = -1;
  param_2[0x113] = -1;
  pcVar4 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
  } while (cVar1 != '\0');
  if (0x100 < ~uVar2 - 1) {
    FUN_180004400("Image file path is too long.\n",param_2,param_1,param_4);
    return 0xfffffff6;
  }
  pcVar4 = param_1;
  do {
    cVar1 = *pcVar4;
    pcVar4 = pcVar4 + 1;
    pcVar4[(longlong)(param_2 + (-1 - (longlong)param_1))] = cVar1;
  } while (cVar1 != '\0');
  uVar2 = FUN_180003270(param_2);
  if ((int)uVar2 == 0) {
    if (param_2[0x123] == '\x01') {
      if (0 < *(int *)(param_2 + 0x110)) {
        iVar3 = 1;
      }
    }
    else {
      iVar3 = -1;
      if (*(longlong *)(param_2 + 0x108) != 0) {
        iVar3 = 1;
      }
    }
    uVar2 = thunk_FUN_1800034e0((longlong)param_2);
    if ((int)uVar2 != 0) {
      if (iVar3 == 1) {
        CloseHandle(*(HANDLE *)(param_2 + 0x108));
      }
      return uVar2 & 0xffffffff;
    }
    param_2[0x114] = '\0';
    param_2[0x115] = '\0';
    param_2[0x116] = '\0';
    param_2[0x117] = '\0';
    uVar2 = 0;
    if (param_2[0x122] == '\x01') {
      uVar2 = 2;
    }
    param_2[0x120] = '\x01';
    param_2[0x121] = '\x01';
  }
  return uVar2;
}

