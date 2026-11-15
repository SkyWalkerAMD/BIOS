
undefined4 FUN_00018d74(char *param_1)

{
  bool bVar1;
  int iVar2;
  undefined4 uVar3;
  FILE *pFVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  char *__s2;
  uint uVar8;
  byte local_79;
  char acStack_78 [84];
  
  local_79 = 0;
  FUN_00018ccc(&local_79);
  if (3 < local_79) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00018fb0,DAT_00018fac,DAT_00018fa8,param_1);
    return 0xffffffff;
  }
  pFVar4 = fopen(DAT_00018f88,DAT_00018f84);
  uVar3 = DAT_00018f90;
  iVar2 = DAT_00018f8c;
  iVar7 = DAT_00018f8c;
  if (pFVar4 == (FILE *)0x0) {
    pFVar4 = fopen(DAT_00018f88,DAT_00018f94);
    if (pFVar4 == (FILE *)0x0) {
      return 0xffffffff;
    }
    fwrite(DAT_00018f98,1,0xe,pFVar4);
LAB_00018f0c:
    fprintf(pFVar4,DAT_00018f9c,param_1);
    fwrite(DAT_00018fa0,1,2,pFVar4);
  }
  else {
    while ((iVar6 = feof(pFVar4), iVar6 == 0 &&
           (pcVar5 = fgets(acStack_78,0x50,pFVar4), pcVar5 != (char *)0x0))) {
      pcVar5 = strchr(acStack_78,0x2c);
      if (pcVar5 != (char *)0x0) {
        __isoc99_sscanf(acStack_78,uVar3,iVar7);
        iVar7 = iVar7 + 0x14;
      }
    }
    fclose(pFVar4);
    pFVar4 = fopen(DAT_00018f88,DAT_00018f94);
    if (pFVar4 == (FILE *)0x0) {
      return 0xffffffff;
    }
    fwrite(DAT_00018f98,1,0xe,pFVar4);
    pcVar5 = DAT_00018f9c;
    uVar8 = (uint)local_79;
    if (uVar8 == 0) goto LAB_00018f0c;
    iVar7 = 0;
    bVar1 = false;
    do {
      while( true ) {
        __s2 = (char *)(iVar2 + iVar7 * 0x14);
        iVar6 = strcmp(param_1,__s2);
        if (iVar6 == 0) break;
        fprintf(pFVar4,pcVar5,__s2);
        uVar8 = (uint)local_79;
        iVar7 = iVar7 + 1;
        if ((int)uVar8 <= iVar7) goto LAB_00018e94;
      }
      bVar1 = true;
      iVar7 = iVar7 + 1;
    } while (iVar7 < (int)uVar8);
LAB_00018e94:
    fprintf(pFVar4,DAT_00018f9c,param_1);
    fwrite(DAT_00018fa0,1,2,pFVar4);
    if (bVar1) goto LAB_00018ec4;
  }
  local_79 = local_79 + 1;
LAB_00018ec4:
  fprintf(pFVar4,DAT_00018fa4,(uint)local_79);
  fclose(pFVar4);
  return 0;
}

