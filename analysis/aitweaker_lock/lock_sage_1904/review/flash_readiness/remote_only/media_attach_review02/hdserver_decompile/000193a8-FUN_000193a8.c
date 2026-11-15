
int FUN_000193a8(undefined4 param_1)

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
  
  __stream = fopen(DAT_000194f0,DAT_000194ec);
  uVar1 = DAT_000194f8;
  iVar5 = DAT_000194f4;
  if (__stream != (FILE *)0x0) {
    iVar6 = 0;
    iVar4 = DAT_000194f4;
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
    iVar4 = FUN_00018ccc(&uStack_71);
    if ((iVar4 == 0) && (iVar6 != 0)) {
      iVar4 = iVar5 + iVar6 * 0x14;
      do {
        while (iVar6 = IsProcRunning(iVar5), iVar6 == 0) {
          iVar6 = iVar5 + 0x14;
          FUN_000191f0(iVar5);
          iVar5 = iVar6;
          if (iVar6 == iVar4) goto LAB_0001947c;
        }
        iVar5 = iVar5 + 0x14;
      } while (iVar5 != iVar4);
    }
  }
LAB_0001947c:
  FUN_000191f0(param_1);
  iVar5 = FUN_00018ccc(local_70);
  if ((iVar5 == 0) && (local_70[0] != '\0')) {
    iVar5 = -2;
  }
  else {
    safe_system(DAT_000194fc);
    iVar5 = FUN_00018b0c(DAT_00019504,DAT_00019500);
    iVar5 = -(uint)(iVar5 == 0);
  }
  return iVar5;
}

