
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_0000914c(undefined8 param_1,undefined8 param_2)

{
  longlong lVar1;
  undefined8 uVar2;
  longlong local_res18;
  undefined8 in_stack_ffffffffffffffe8;
  
  lVar1 = (**(code **)(DAT_000104c0 + 0x140))(&DAT_0000ead0,0);
  if (-1 < lVar1) {
    *(code **)(local_res18 + 0x80) = FUN_00009040;
    uVar2 = 0x28;
    _DAT_0000ed60 = param_1;
    DAT_0000ed68 = param_2;
    FUN_00000340((undefined8 *)&DAT_00010540,0x28,0);
    FUN_0000e128(param_1,uVar2,0xed40,DAT_0000ed68,in_stack_ffffffffffffffe8,0xedc0);
  }
  return;
}

