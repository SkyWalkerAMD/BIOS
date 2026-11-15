
undefined8 Observed_PendingProducer(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong *plVar1;
  bool bVar2;
  bool bVar3;
  longlong *plVar4;
  longlong *plVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong lVar8;
  undefined8 uVar9;
  
  uVar9 = 0x8000000000000015;
  if ((DAT_000aff30 == 0) || (*(longlong *)(DAT_000aff30 + 8) == 0)) {
    uVar9 = 0;
  }
  else {
    for (plVar1 = *(longlong **)(DAT_000aff30 + 0x10); plVar1 != (longlong *)0x0;
        plVar1 = (longlong *)plVar1[4]) {
      if ((plVar1[1] == 2) || (plVar1[1] == 8)) {
        FUN_0003fab4(3,0,param_3,plVar1);
      }
    }
    plVar1 = *(longlong **)(DAT_000aff30 + 0x10);
    bVar3 = false;
joined_r0x0003ff50:
    if (plVar1 != (longlong *)0x0) {
      bVar2 = true;
      if ((DAT_000aff80 != 0) && (uVar6 = 0, DAT_000aff68 != 0)) {
        plVar4 = (longlong *)(DAT_000aff80 + 8);
        do {
          if (*plVar4 == *plVar1) {
            uVar9 = 0;
            goto LAB_0003ff9c;
          }
          uVar6 = uVar6 + 1;
          plVar4 = plVar4 + 6;
        } while (uVar6 < DAT_000aff68);
      }
      uVar9 = 0x800000000000000e;
      bVar2 = bVar3;
LAB_0003ff9c:
      plVar4 = plVar1;
      if (plVar1[1] == 2) {
        if (bVar2) goto code_r0x0003ffac;
LAB_00040044:
        if (DAT_000baa68 != 0) goto LAB_0004005a;
        lVar8 = 0;
        lVar7 = 0;
        goto LAB_00040052;
      }
      if (plVar1[1] == 8) {
        if (!bVar2) goto LAB_00040044;
        if ((DAT_000aff22 != '\x01') || (lVar8 = DAT_000aff40, DAT_000aff40 == 0)) {
          plVar5 = (longlong *)plVar1[4];
          if (plVar5 != (longlong *)0x0) {
            do {
              if ((*plVar5 == *plVar1) && (plVar4 = plVar5, plVar5[1] == 2)) break;
              plVar5 = (longlong *)plVar5[4];
              plVar4 = plVar1;
            } while (plVar5 != (longlong *)0x0);
          }
          goto LAB_0004005a;
        }
        goto LAB_0003fff6;
      }
      goto LAB_0004005a;
    }
  }
  return uVar9;
code_r0x0003ffac:
  plVar5 = (longlong *)plVar1[4];
  if (plVar5 == (longlong *)0x0) {
    lVar8 = *plVar1;
  }
  else {
    lVar8 = *plVar1;
    do {
      if ((*plVar5 == lVar8) && (plVar5[1] == 1)) {
        FUN_0003fab4(1,lVar8,param_3,(longlong *)0x0);
        plVar1 = *(longlong **)(DAT_000aff30 + 0x10);
        bVar3 = bVar2;
        goto joined_r0x0003ff50;
      }
      plVar5 = (longlong *)plVar5[4];
    } while (plVar5 != (longlong *)0x0);
  }
LAB_0003fff6:
  lVar7 = 1;
LAB_00040052:
  FUN_0003fab4(lVar7,lVar8,param_3,plVar1);
LAB_0004005a:
  if (plVar4 != (longlong *)0x0) {
    plVar4 = (longlong *)plVar4[4];
  }
  plVar1 = plVar4;
  bVar3 = false;
  goto joined_r0x0003ff50;
}

