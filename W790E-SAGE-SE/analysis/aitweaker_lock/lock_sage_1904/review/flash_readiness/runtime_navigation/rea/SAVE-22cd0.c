
void FUN_00022cd0(void)

{
  longlong *plVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  
  uVar2 = 0;
  uVar4 = uVar2;
  uVar3 = uVar2;
  if (DAT_00093918 != 0) {
    do {
      if (DAT_00093910 == 0) goto LAB_00022d78;
      plVar1 = (longlong *)(DAT_00093910 + 0x10 + uVar4);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      plVar1 = (longlong *)(DAT_00093910 + 8 + uVar4);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      plVar1 = (longlong *)(DAT_00093910 + 0x18 + uVar4);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      plVar1 = (longlong *)(DAT_00093910 + 0x40 + uVar4);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      uVar3 = uVar3 + 1;
      uVar4 = uVar4 + 0x48;
    } while (uVar3 < DAT_00093918);
  }
  if (DAT_00093910 != 0) {
    FUN_00005908(&DAT_00093910);
  }
LAB_00022d78:
  DAT_00093918 = 0;
  uVar4 = uVar2;
  if (DAT_00093900 != 0) {
    do {
      if (DAT_00093910 == 0) break;
      plVar1 = (longlong *)(DAT_00093908 + 0x10 + uVar2);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      plVar1 = (longlong *)(DAT_00093908 + 8 + uVar2);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      plVar1 = (longlong *)(DAT_00093908 + 0x18 + uVar2);
      if (*plVar1 != 0) {
        FUN_00005908(plVar1);
      }
      uVar4 = uVar4 + 1;
      uVar2 = uVar2 + 0x48;
    } while (uVar4 < DAT_00093900);
  }
  if (DAT_00093908 != 0) {
    FUN_00005908(&DAT_00093908);
  }
  DAT_00093900 = 0;
  return;
}

