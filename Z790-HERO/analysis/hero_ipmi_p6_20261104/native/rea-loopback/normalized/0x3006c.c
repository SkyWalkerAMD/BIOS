uint FUN_0003006c(undefined8 param_1,uint param_2)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  longlong *plVar4;
  if (DAT_0018f1da != '\0') {
    uVar3 = 0;
    plVar4 = DAT_001937f8;
    while( true ) {
      if ((plVar4 == (longlong *)0x0) || (uVar3 == DAT_00193688)) goto LAB_0003011c;
      if (*(short *)((longlong)plVar4 + 0x3a) == 1) {
        iVar1 = (uint)*(byte *)(plVar4 + 2) * 4 + 2;
      }
      else {
        iVar1 = (*(byte *)(plVar4 + 2) + 1) * (uint)*(ushort *)((longlong)plVar4 + 0x3a) * 2;
      }
      uVar2 = iVar1 + 0x40;
      if ((*plVar4 == 0) && (uVar2 == param_2)) break;
      uVar3 = uVar3 + uVar2 + (-uVar2 & 7);
      plVar4 = (longlong *)((longlong)plVar4 + (ulonglong)uVar2 + (ulonglong)(-uVar2 & 7));
    }
    (**(code **)(DAT_00180188 + 0x160))(plVar4,param_1,param_2);
    if (uVar3 != 0) {
      return uVar3;
    }
  }
LAB_0003011c:
  if (DAT_001936a8 <= DAT_00193688 + (-param_2 & 7) + param_2) {
    DAT_001937f8 = (longlong *)
                   FUN_00001450((longlong)DAT_001937f8,(ulonglong)DAT_001936a8,
                                (ulonglong)(DAT_001936a8 + 0x2000));
    DAT_001936a8 = DAT_001936a8 + 0x2000;
  }
  (**(code **)(DAT_00180188 + 0x160))
            ((ulonglong)DAT_00193688 + (longlong)DAT_001937f8,param_1,param_2);
  uVar3 = DAT_00193688;
  DAT_00193688 = DAT_00193688 + (-param_2 & 7) + param_2;
  return uVar3;
}
