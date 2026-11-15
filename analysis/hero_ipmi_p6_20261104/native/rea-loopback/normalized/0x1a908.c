longlong FUN_0001a908(ulonglong param_1,ulonglong *param_2)
{
  int *piVar1;
  ushort uVar2;
  ulonglong uVar3;
  longlong *plVar4;
  longlong lVar5;
  longlong local_res10;
  *param_2 = 0;
  local_res10 = 0;
  if ((uint)param_1 < *DAT_001937f0) {
    lVar5 = (ulonglong)DAT_001937f0[(param_1 & 0xffffffff) + 1] + (longlong)DAT_001937f0;
    if (lVar5 != 0) {
      if ((*(byte *)(lVar5 + 0x68) & 4) == 0) {
        if (((*(uint *)(lVar5 + 0x68) & 0x1000) == 0) &&
           ((0x39 < (uint)param_1 || ((0x3ff800003fcfffeU >> (param_1 & 0x3f) & 1) == 0)))) {
          uVar2 = *(ushort *)(lVar5 + 0x78);
          *param_2 = (ulonglong)uVar2;
          lVar5 = FUN_000274f8(lVar5,&local_res10,0,(ulonglong)uVar2);
          if (-1 < lVar5) {
            return local_res10;
          }
          *param_2 = 0;
          return local_res10;
        }
        piVar1 = (int *)(lVar5 + 0x60);
        *param_2 = 0;
        if (*piVar1 == 0) {
          *piVar1 = 7;
        }
        lVar5 = FUN_0000130c(lVar5 + 0x10,lVar5,piVar1,(longlong *)param_2);
        return lVar5;
      }
      if (DAT_001801c0 == 0) {
        if (*(short *)(lVar5 + 0x78) != 0) {
          uVar2 = *(ushort *)(lVar5 + 0x78);
          *param_2 = (ulonglong)uVar2;
          lVar5 = FUN_000014c8((ulonglong)uVar2);
          return lVar5;
        }
      }
      else {
        plVar4 = (longlong *)((param_1 & 0xffffffff) * 0x10 + DAT_001801c0);
        if ((plVar4 != (longlong *)0x0) && (uVar3 = plVar4[1], uVar3 != 0)) {
          *param_2 = uVar3;
          lVar5 = FUN_000014c8(uVar3);
          if (*plVar4 == 0) {
            return lVar5;
          }
          (**(code **)(DAT_00180188 + 0x160))(lVar5,*plVar4,*param_2);
          return lVar5;
        }
      }
      *param_2 = 0;
    }
  }
  return 0;
}
