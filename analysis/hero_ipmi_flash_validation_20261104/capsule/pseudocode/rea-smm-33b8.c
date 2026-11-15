
ulonglong FUN_000033b8(undefined8 *param_1,undefined8 *param_2)

{
  longlong lVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  longlong *plVar4;
  longlong *plVar5;
  longlong *plVar6;
  longlong *local_res8;
  
  if ((param_1 != (undefined8 *)0x0) && (plVar6 = (longlong *)*param_1, plVar6 != (longlong *)0x0))
  {
    local_res8 = plVar6;
    lVar1 = FUN_00004650(plVar6,(longlong *)&DAT_000050b0,0x10);
    if (lVar1 == 0) {
      plVar5 = (longlong *)((ulonglong)*(ushort *)((longlong)plVar6 + 0x1c) + (longlong)plVar6);
      if (plVar5 < plVar6) {
        return 0x800000000000001a;
      }
      *param_1 = plVar5;
      plVar4 = plVar6;
      plVar6 = plVar5;
    }
    else {
      lVar1 = FUN_00002d84(plVar6,0x2000000,&local_res8);
      plVar4 = local_res8;
      if (lVar1 < 0) {
        return 0x800000000000001a;
      }
    }
    uVar2 = FUN_00002d30((longlong)plVar4);
    if (((char)uVar2 != '\0') &&
       (uVar3 = (ulonglong)((int)plVar4[3] - (uint)*(ushort *)((longlong)plVar4 + 0x1c)),
       uVar3 < 0x2001001)) {
      if (param_2 != (undefined8 *)0x0) {
        *param_2 = plVar4;
      }
      if ((DAT_00005870 != 0) &&
         (lVar1 = (**(code **)(DAT_00005870 + 0x10))(DAT_00005a78,DAT_00005a70), -1 < lVar1)) {
        if (*DAT_00005a78 == 0x44414224) {
          return 0x8000000000000019;
        }
        lVar1 = FUN_00004650(plVar4 + 5,(longlong *)&DAT_00005060,0x10);
        if (lVar1 == 0) {
          uVar3 = FUN_00003008((longlong)plVar4,(longlong)plVar6,uVar3);
        }
        else {
          uVar3 = FUN_000031d4((longlong)plVar4,(longlong)plVar6,uVar3);
        }
        if (-1 < (longlong)uVar3) {
          uVar3 = FUN_00002c64((longlong)plVar4,(longlong)plVar6);
          return uVar3;
        }
        return uVar3;
      }
    }
  }
  return 0x800000000000001a;
}

