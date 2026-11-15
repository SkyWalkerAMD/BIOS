
longlong FUN_0001ccbc(uint param_1,uint param_2,ulonglong param_3,ushort *param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  ushort *puVar3;
  longlong lVar4;
  uint local_res10 [2];
  ulonglong local_res18;
  ushort *local_res20;
  
  local_res20 = (ushort *)0x0;
  lVar4 = 0;
  if (param_1 < *DAT_000baaf8) {
    lVar4 = (ulonglong)DAT_000baaf8[(ulonglong)param_1 + 1] + (longlong)DAT_000baaf8;
  }
  local_res10[0] = param_2;
  local_res18 = param_3;
  lVar2 = FUN_0001cabc((ulonglong)param_1,local_res10,&local_res18,param_4,(longlong *)&local_res20)
  ;
  uVar1 = local_res18;
  puVar3 = local_res20;
  if (lVar2 < 0) {
    puVar3 = param_4;
  }
  lVar2 = FUN_0001cde4(1,DAT_000afcd8,param_1,local_res10[0],local_res18,(undefined1 *)puVar3);
  if ((param_1 == 1) && (-1 < lVar2)) {
    if (DAT_000afdd0 != 0) {
      *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
    }
    lVar2 = Observed_NativeCommit(1,(longlong)puVar3,uVar1);
  }
  if ((puVar3 != param_4) && (puVar3 != (ushort *)0x0)) {
    (**(code **)(DAT_000afbc8 + 0x48))(puVar3);
  }
  if ((((0x39 < param_1) || ((0x3ffffffff5efe10U >> ((ulonglong)param_1 & 0x3f) & 1) == 0)) &&
      (param_1 != 0xf017)) && ((lVar4 == 0 || ((*(byte *)(lVar4 + 0x68) & 2) == 0)))) {
    FUN_0000fd18(0xffff001a,&LAB_000069ec);
    DAT_000afe10 = 1;
    DAT_000afe11 = 1;
  }
  return lVar2;
}

