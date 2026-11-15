
undefined2 FUN_00028634(longlong *param_1,undefined8 *param_2)

{
  byte *pbVar1;
  undefined2 uVar2;
  uint local_res18 [4];
  
  uVar2 = 0xfffe;
  local_res18[0] = FUN_00028250(param_1);
  pbVar1 = FUN_0002847c((longlong)param_1,local_res18,param_2);
  if (pbVar1 != (byte *)0x0) {
    if (*pbVar1 == 0x12) {
      uVar2 = *(undefined2 *)(pbVar1 + 4);
    }
    else if (*pbVar1 == 0x14) {
      uVar2 = *(undefined2 *)(pbVar1 + 6);
    }
  }
  return uVar2;
}

