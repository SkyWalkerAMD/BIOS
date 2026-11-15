
undefined4 FUN_00011614(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = DAT_00011684;
  iVar5 = 0;
  iVar4 = DAT_00011680;
  iVar6 = param_1;
  do {
    while (iVar2 = sigwrap_read(*(undefined4 *)(iVar1 + 4),iVar6,iVar4), -1 < iVar2) {
      iVar4 = iVar4 - iVar2;
      iVar5 = iVar5 + iVar2;
      if (iVar4 < 1) {
        return 0;
      }
      iVar6 = param_1 + iVar5;
    }
    piVar3 = __errno_location();
  } while (*piVar3 == 0xb || *piVar3 == 4);
  return 0xffffffff;
}

