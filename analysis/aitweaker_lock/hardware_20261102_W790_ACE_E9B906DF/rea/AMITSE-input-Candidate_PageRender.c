
undefined8 Candidate_PageRender(longlong param_1)

{
  longlong *plVar1;
  longlong lVar2;
  longlong lVar3;
  undefined8 uVar4;
  int *piVar5;
  uint uVar6;
  uint uVar7;
  ulonglong uVar8;
  undefined8 uVar9;
  short sVar10;
  ulonglong uVar11;
  
  uVar4 = DAT_00082648;
  uVar6 = 0;
  DAT_00082648 = 7;
  piVar5 = (int *)PTR_DAT_0006b7f0;
  do {
    if (*piVar5 == 0) break;
    uVar6 = uVar6 + 1;
    piVar5 = piVar5 + 6;
  } while (uVar6 < 6);
  lVar2 = *(longlong *)(*(longlong *)(param_1 + 0x50) + (ulonglong)uVar6 * 8);
  FUN_00017288(param_1);
  lVar3 = DAT_00092260;
  sVar10 = *(short *)(param_1 + 0x2c);
  uVar9 = *(undefined8 *)(param_1 + 0x20);
  if (sVar10 == 0) {
    sVar10 = *(short *)(DAT_00092260 + 8);
    uVar9 = DAT_00092b30;
  }
  FUN_00017224(param_1,1,uVar9,sVar10);
  sVar10 = *(short *)(param_1 + 0x2e);
  uVar9 = *(undefined8 *)(param_1 + 0x20);
  if (sVar10 == 0) {
    sVar10 = *(short *)(lVar3 + 10);
    uVar9 = DAT_00092b30;
  }
  FUN_00017224(param_1,4,uVar9,sVar10);
  FUN_00017224(param_1,3,DAT_00092b30,0xa5);
  if ((*(char *)(DAT_00082748 + 0x58) != '\0') && (*(int *)(DAT_00082748 + 0x5c) != 0)) {
    if (*(int *)(DAT_00082748 + 0x5c) == 3) {
      FUN_0001696c(param_1);
    }
    *(undefined4 *)(DAT_00082748 + 0x5c) = 0;
  }
  uVar11 = (ulonglong)*(uint *)(lVar2 + 0x44);
  if ((((*(uint *)(lVar2 + 0x44) == 0xffffffff) ||
       (plVar1 = (longlong *)(*(longlong *)(lVar2 + 0x48) + uVar11 * 8), plVar1 == (longlong *)0x0))
      || (lVar3 = *plVar1, lVar3 == 0)) || (*(char *)(lVar3 + 0x6b) != '\x01')) {
    uVar8 = 0;
    if (*(int *)(param_1 + 0x4c) != 0) {
      do {
        uVar7 = (uint)uVar8;
        (*(code *)PTR_FUN_0006af20)(*(undefined8 *)(*(longlong *)(param_1 + 0x50) + uVar8 * 8));
        if ((uVar7 == uVar6) && (*(int *)(lVar2 + 0x44) != (int)uVar11)) {
          FUN_00017288(param_1);
          uVar11 = (ulonglong)*(uint *)(lVar2 + 0x44);
          uVar7 = 0;
        }
        uVar8 = (ulonglong)(uVar7 + 1);
      } while (uVar7 + 1 < *(uint *)(param_1 + 0x4c));
    }
  }
  else {
    (*(code *)PTR_FUN_0006af20)(lVar2);
  }
  DAT_00082648 = uVar4;
  return 0;
}

