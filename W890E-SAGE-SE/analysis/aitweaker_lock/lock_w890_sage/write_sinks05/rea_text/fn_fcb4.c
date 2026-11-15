
void WS05_fcb4(longlong param_1,longlong *param_2,longlong *param_3)

{
  ulonglong uVar1;
  longlong lVar2;
  longlong lVar3;
  int iVar4;
  
  *param_2 = 0;
  iVar4 = 0;
  lVar2 = 0xffff0001;
  lVar3 = 0;
  do {
    if (param_1 == lVar2) {
      lVar2 = (longlong)iVar4 + 2;
      *param_2 = lVar2;
      uVar1 = *(ulonglong *)(&DAT_000a9760 + lVar2 * 8);
      while ((uVar1 != 0 && ((uVar1 & 0xffff0000) != 0xffff0000))) {
        lVar2 = lVar2 + 1;
        uVar1 = *(ulonglong *)(&DAT_000a9760 + lVar2 * 8);
      }
      *param_3 = lVar2 + -1;
      return;
    }
    lVar3 = lVar3 + 1;
    iVar4 = iVar4 + 1;
    lVar2 = *(longlong *)(&DAT_000a9760 + lVar3 * 8);
  } while (lVar2 != 0);
  return;
}

