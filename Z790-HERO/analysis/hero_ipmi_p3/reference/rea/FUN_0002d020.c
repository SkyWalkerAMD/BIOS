ushort FUN_0002d020(longlong *param_1,short param_2,short param_3)
{
  uint uVar1;
  uint *puVar2;
  longlong lVar3;
  ushort uVar4;
  longlong *plVar5;
  undefined1 local_48 [16];
  short local_38;
  short local_36;
  uVar4 = 0;
  if (DAT_00193660 == (uint *)0x0) {
    DAT_0019367c = 0x80;
    DAT_00193660 = (uint *)FUN_000014c8(0x80);
    DAT_001936ac = 4;
  }
  puVar2 = DAT_00193660;
  uVar1 = *DAT_00193660;
  if (uVar1 != 0) {
    do {
      plVar5 = (longlong *)((ulonglong)puVar2[(ulonglong)uVar4 + 1] + DAT_00193640);
      lVar3 = FUN_000b1b20(param_1,plVar5,0x10);
      if (((lVar3 == 0) && (param_2 == (short)plVar5[2])) &&
         (param_3 == *(short *)((longlong)plVar5 + 0x12))) break;
      uVar4 = uVar4 + 1;
    } while (uVar4 < uVar1);
  }
  if (uVar1 <= uVar4) {
    (**(code **)(DAT_00180188 + 0x160))(local_48,param_1,0x10);
    uVar4 = (ushort)*DAT_00193660;
    local_38 = param_2;
    local_36 = param_3;
    FUN_000301a4(local_48);
  }
  return uVar4;
}