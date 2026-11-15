
undefined8 FUN_0003905c(void)

{
  longlong *plVar1;
  longlong *plVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong lVar5;
  
  if ((DAT_00193728 == 0) || (DAT_00193730 == 0)) {
    if (DAT_0018f1f8 != 0) {
      do {
        if (*(longlong *)(DAT_0018f1f8 + 8) == 0) break;
        FUN_00038e9c(*(longlong *)(DAT_0018f1f8 + 8));
      } while (DAT_0018f1f8 != 0);
      if (DAT_0018f1f8 != 0) {
        FUN_000013d0(&DAT_0018f1f8);
        DAT_0018f1f8 = 0;
      }
    }
  }
  else {
    uVar4 = 0;
    uVar3 = DAT_00193730;
    lVar5 = DAT_00193728;
    if (DAT_00193730 != 0) {
      do {
        plVar1 = *(longlong **)(DAT_0018f1f8 + 8);
        while (plVar2 = plVar1, plVar2 != (longlong *)0x0) {
          plVar1 = (longlong *)plVar2[5];
          uVar3 = DAT_00193730;
          if (*plVar2 == *(longlong *)(lVar5 + uVar4 * 8)) {
            FUN_00038e9c((longlong)plVar2);
            uVar3 = DAT_00193730;
            lVar5 = DAT_00193728;
          }
        }
        uVar4 = uVar4 + 1;
      } while (uVar4 < uVar3);
    }
  }
  return 0;
}

