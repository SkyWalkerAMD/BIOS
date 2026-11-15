
undefined8 FUN_00002d84(longlong *param_1,ulonglong param_2,undefined8 *param_3)

{
  int iVar1;
  longlong lVar2;
  longlong *plVar3;
  
  iVar1 = DAT_000051c8;
  if (param_1 != (longlong *)0x0) {
    plVar3 = (longlong *)((longlong)param_1 + ((param_2 & 0xffffffff) - 0x2c));
    while (param_1 < plVar3) {
      if (((((int)*param_1 == iVar1) && (*(char *)((longlong)param_1 + 0x12) == '\x02')) &&
          (lVar2 = FUN_00004650((longlong *)&DAT_000051c8,param_1,0x10), lVar2 == 0)) &&
         (lVar2 = FUN_00004650((longlong *)&DAT_00005230,(longlong *)((longlong)param_1 + 0x1c),0x10
                              ), lVar2 == 0)) {
        if ((ulonglong)(*(uint *)((longlong)param_1 + 0x14) & 0xffffff) <
            (ulonglong)*(uint *)((longlong)param_1 + 0x3c) + 0x2c) {
          return 0x800000000000000e;
        }
        lVar2 = FUN_00004650((longlong *)((longlong)param_1 + 0x2c),(longlong *)&DAT_000050b0,0x10);
        if (lVar2 != 0) {
          return 0x800000000000000e;
        }
        if (param_3 != (undefined8 *)0x0) {
          *param_3 = (longlong *)((longlong)param_1 + 0x2c);
        }
        return 0;
      }
      param_1 = (longlong *)((longlong)param_1 + 4);
      if (param_1 == (longlong *)0x0) {
        return 0x800000000000000e;
      }
    }
  }
  return 0x800000000000000e;
}

