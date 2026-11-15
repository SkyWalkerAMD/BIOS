
byte FUN_0000dd6c(uint param_1)

{
  longlong lVar1;
  longlong lVar2;
  byte bVar3;
  longlong lVar4;
  longlong local_res10 [3];
  
  lVar2 = 0;
  local_res10[0] = 0;
  lVar4 = lVar2;
  if (DAT_00093948 == 0) {
    lVar1 = -0x7ffffffffffffffa;
  }
  else {
    lVar1 = FUN_0000dd20(param_1,local_res10);
    lVar2 = local_res10[0];
  }
  bVar3 = (byte)lVar4;
  if (-1 < lVar1) {
    bVar3 = (byte)(*(uint *)(lVar2 + 0x14) >> 4) & 1;
  }
  return bVar3;
}

