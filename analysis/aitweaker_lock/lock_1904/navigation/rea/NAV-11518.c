
longlong Candidate_ReadVarstoreField(uint param_1,uint param_2,ulonglong param_3,ushort *param_4)

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
  if (param_1 < *DAT_00092278) {
    lVar4 = (ulonglong)DAT_00092278[(ulonglong)param_1 + 1] + (longlong)DAT_00092278;
  }
  local_res10[0] = param_2;
  local_res18 = param_3;
  lVar2 = FUN_00011344((ulonglong)param_1,local_res10,&local_res18,param_4,(longlong *)&local_res20)
  ;
  uVar1 = local_res18;
  puVar3 = local_res20;
  if (lVar2 < 0) {
    puVar3 = param_4;
  }
  local_res20 = puVar3;
  lVar2 = FUN_0001163c(1,DAT_00082650,param_1,local_res10[0],local_res18,(undefined8 *)puVar3);
  if ((param_1 == 1) && (-1 < lVar2)) {
    if (DAT_00082748 != 0) {
      *(undefined1 *)(DAT_00082748 + 0x58) = 1;
    }
    lVar2 = FUN_000111b4(1,(longlong)puVar3,uVar1);
  }
  if (puVar3 != param_4) {
    FUN_00005958((longlong *)&local_res20);
  }
  if ((((0x39 < param_1) || ((0x3ffffffff5efe10U >> ((ulonglong)param_1 & 0x3f) & 1) == 0)) &&
      (param_1 != 0xf017)) && ((lVar4 == 0 || ((*(byte *)(lVar4 + 0x68) & 2) == 0)))) {
    FUN_00005ab8(0xffff001a,&LAB_00006370);
    DAT_00082788 = 1;
    DAT_00082789 = 1;
  }
  return lVar2;
}

