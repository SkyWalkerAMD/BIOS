
int FUN_00018bfc(undefined4 param_1)

{
  undefined4 uVar1;
  FILE *__stream;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined1 uStack_71;
  char local_70 [80];
  
  __stream = fopen(DAT_00018d44,DAT_00018d40);
  uVar1 = DAT_00018d4c;
  iVar5 = DAT_00018d48;
  if (__stream != (FILE *)0x0) {
    iVar6 = 0;
    iVar4 = DAT_00018d48;
    while ((iVar3 = feof(__stream), iVar3 == 0 &&
           (pcVar2 = fgets(local_70,0x50,__stream), pcVar2 != (char *)0x0))) {
      pcVar2 = strchr(local_70,0x2c);
      if (pcVar2 != (char *)0x0) {
        __isoc99_sscanf(local_70,uVar1,iVar4);
        iVar6 = iVar6 + 1;
        iVar4 = iVar4 + 0x14;
      }
    }
    fclose(__stream);
    iVar4 = FUN_00018520(&uStack_71);
    if ((iVar4 == 0) && (iVar6 != 0)) {
      iVar4 = iVar5 + iVar6 * 0x14;
      do {
        while (iVar6 = IsProcRunning(iVar5), iVar6 == 0) {
          iVar6 = iVar5 + 0x14;
          FUN_00018a44(iVar5);
          iVar5 = iVar6;
          if (iVar6 == iVar4) goto LAB_00018cd0;
        }
        iVar5 = iVar5 + 0x14;
      } while (iVar5 != iVar4);
    }
  }
LAB_00018cd0:
  FUN_00018a44(param_1);
  iVar5 = FUN_00018520(local_70);
  if ((iVar5 == 0) && (local_70[0] != '\0')) {
    iVar5 = -2;
  }
  else {
    safe_system(DAT_00018d50);
    iVar5 = FUN_00018360(DAT_00018d58,DAT_00018d54);
    iVar5 = -(uint)(iVar5 == 0);
  }
  return iVar5;
}

