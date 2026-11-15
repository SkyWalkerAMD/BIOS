
void FUN_0001f32c(short *param_1)

{
  longlong lVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  short sVar6;
  ulonglong uVar7;
  short sVar8;
  ulonglong uVar5;
  
  uVar5 = 0;
  sVar6 = 0;
  if ((char)param_1 != '\0') {
    param_1 = (short *)&DAT_00094360;
    cVar2 = FUN_0002ae44(&DAT_00094360,3);
    if (cVar2 != '\0') {
      return;
    }
  }
  if (DAT_000bab30 != (short *)0x0) {
    uVar7 = uVar5;
    sVar8 = sVar6;
    if (DAT_000bab90 != 0) {
      do {
        param_1 = (short *)(DAT_000bab88 + uVar7 * 0x48);
        if (param_1 == DAT_000bab30) {
          sVar8 = 1;
        }
        uVar7 = (ulonglong)((int)uVar7 + 1);
      } while (uVar7 < DAT_000bab90);
      if (sVar8 != 0) {
        sVar6 = *DAT_000bab30;
        goto LAB_0001f3ae;
      }
    }
    DAT_000bab30 = (short *)0x0;
  }
LAB_0001f3ae:
  FUN_0001c078();
  FUN_0001c17c(param_1,0);
  FUN_0001c958(1,DAT_000baaa8,DAT_000afe20);
  FUN_0000fd18(0xffff0019,&LAB_000069ec);
  DAT_000bab30 = FUN_00013298(sVar6);
  if (DAT_000bab30 != (short *)0x0) {
    FUN_0001ccbc(0xf,0,2,(ushort *)(DAT_000bab30 + 0x1c));
  }
  DAT_000afdc8 = DAT_000afdc8 & -(DAT_000afdc9 != '\0');
  FUN_0003f5cc(2);
  FUN_00049c1c();
  if (DAT_000afdd0 != 0) {
    *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
    piVar3 = (int *)PTR_DAT_00094670;
    do {
      if (*piVar3 == 0) break;
      uVar4 = (int)uVar5 + 1;
      uVar5 = (ulonglong)uVar4;
      piVar3 = piVar3 + 6;
    } while (uVar4 < 6);
    lVar1 = *(longlong *)
             (*(longlong *)
               (*(longlong *)
                 (*(longlong *)(DAT_000afdd0 + 0x30) + (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 8
                 ) + 0x50) + uVar5 * 8);
    if (((*(int *)(lVar1 + 0x3c) != 0) && (*(int *)(lVar1 + 0x44) != -1)) &&
       (lVar1 = *(longlong *)(*(longlong *)(lVar1 + 0x48) + (ulonglong)*(uint *)(lVar1 + 0x44) * 8),
       *(char *)(lVar1 + 0x6b) == '\x01')) {
      *(undefined1 *)(lVar1 + 0x6b) = 0;
    }
  }
  DAT_000afe11 = 0;
  FUN_00010704(&DAT_000933a8);
  return;
}

