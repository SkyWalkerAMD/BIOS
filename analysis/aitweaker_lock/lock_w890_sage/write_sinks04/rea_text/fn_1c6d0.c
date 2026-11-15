
undefined8 * FUN_0001c6d0(ulonglong param_1,ulonglong *param_2)

{
  int *piVar1;
  ushort uVar2;
  ulonglong uVar3;
  longlong lVar4;
  longlong *plVar5;
  undefined8 *puVar6;
  undefined8 *local_res10;
  
  *param_2 = 0;
  local_res10 = (undefined8 *)0x0;
  if (((uint)param_1 < *DAT_000baaf8) &&
     (puVar6 = (undefined8 *)
               ((ulonglong)DAT_000baaf8[(param_1 & 0xffffffff) + 1] + (longlong)DAT_000baaf8),
     puVar6 != (undefined8 *)0x0)) {
    if ((*(byte *)(puVar6 + 0xd) & 4) == 0) {
      if (((*(uint *)(puVar6 + 0xd) & 0x1000) == 0) &&
         ((0x39 < (uint)param_1 || ((0x3ff800003fcfffeU >> (param_1 & 0x3f) & 1) == 0)))) {
        uVar2 = *(ushort *)(puVar6 + 0xf);
        *param_2 = (ulonglong)uVar2;
        lVar4 = FUN_00032e3c(puVar6,(longlong *)&local_res10,0,(ulonglong)uVar2);
        if (-1 < lVar4) {
          return local_res10;
        }
        *param_2 = 0;
        return local_res10;
      }
      piVar1 = (int *)(puVar6 + 0xc);
      if (*piVar1 == 0) {
        *piVar1 = 7;
      }
      puVar6 = FUN_00007758(puVar6 + 2,puVar6,piVar1,(longlong *)param_2);
      return puVar6;
    }
    if (DAT_000afcd8 == 0) {
      if (*(short *)(puVar6 + 0xf) != 0) {
        uVar2 = *(ushort *)(puVar6 + 0xf);
        *param_2 = (ulonglong)uVar2;
        puVar6 = FUN_00059b50(param_1,(ulonglong)uVar2);
        return puVar6;
      }
    }
    else {
      plVar5 = (longlong *)((param_1 & 0xffffffff) * 0x10 + DAT_000afcd8);
      if ((plVar5 != (longlong *)0x0) && (uVar3 = plVar5[1], uVar3 != 0)) {
        *param_2 = uVar3;
        puVar6 = FUN_00059b50(param_1,uVar3);
        if (*plVar5 == 0) {
          return puVar6;
        }
        (**(code **)(DAT_000afbc8 + 0x160))(puVar6,*plVar5,*param_2);
        return puVar6;
      }
    }
  }
  return (undefined8 *)0x0;
}

