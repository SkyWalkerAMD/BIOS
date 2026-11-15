
longlong FUN_00039118(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong *plVar1;
  bool bVar2;
  longlong *plVar3;
  longlong *plVar4;
  ulonglong uVar5;
  longlong lVar6;
  longlong lVar7;
  longlong lVar8;
  
  bVar2 = false;
  lVar8 = -0x7fffffffffffffeb;
  if ((DAT_0018f1f8 == 0) || (*(longlong *)(DAT_0018f1f8 + 8) == 0)) {
    lVar8 = 0;
  }
  else {
    for (plVar1 = *(longlong **)(DAT_0018f1f8 + 0x10); plVar1 != (longlong *)0x0;
        plVar1 = (longlong *)plVar1[4]) {
      if ((plVar1[1] == 2) || (plVar1[1] == 8)) {
        FUN_00038f44(3,0,param_3,plVar1);
      }
    }
    plVar1 = *(longlong **)(DAT_0018f1f8 + 0x10);
joined_r0x0003918f:
    if (plVar1 != (longlong *)0x0) {
      lVar8 = -0x7ffffffffffffff2;
      if ((DAT_0018f1a0 != 0) && (uVar5 = 0, DAT_0018f190 != 0)) {
        plVar3 = (longlong *)(DAT_0018f1a0 + 8);
        do {
          if (*plVar3 == *plVar1) {
            lVar8 = 0;
            break;
          }
          uVar5 = uVar5 + 1;
          plVar3 = plVar3 + 6;
        } while (uVar5 < DAT_0018f190);
      }
      if (lVar8 == 0) {
        bVar2 = true;
      }
      plVar3 = plVar1;
      if (plVar1[1] == 2) {
        if (bVar2) goto code_r0x000391f5;
LAB_0003927e:
        if (DAT_00193728 != 0) goto LAB_00039294;
        lVar7 = 0;
        lVar6 = 0;
        goto LAB_0003928c;
      }
      if (plVar1[1] == 8) {
        if (!bVar2) goto LAB_0003927e;
        if ((DAT_0018f1da != '\x01') || (lVar7 = DAT_0018f1e0, DAT_0018f1e0 == 0)) {
          plVar4 = (longlong *)plVar1[4];
          if (plVar4 != (longlong *)0x0) {
            do {
              if ((*plVar4 == *plVar1) && (plVar3 = plVar4, plVar4[1] == 2)) break;
              plVar4 = (longlong *)plVar4[4];
              plVar3 = plVar1;
            } while (plVar4 != (longlong *)0x0);
          }
          goto LAB_00039294;
        }
        goto LAB_00039218;
      }
      goto LAB_00039294;
    }
  }
  return lVar8;
code_r0x000391f5:
  plVar4 = (longlong *)plVar1[4];
  if (plVar4 != (longlong *)0x0) {
    do {
      if ((*plVar4 == *plVar1) && (plVar4[1] == 1)) {
        FUN_00038f44(1,*plVar1,param_3,(longlong *)0x0);
        plVar1 = *(longlong **)(DAT_0018f1f8 + 0x10);
        goto joined_r0x0003918f;
      }
      plVar4 = (longlong *)plVar4[4];
    } while (plVar4 != (longlong *)0x0);
  }
  lVar7 = *plVar1;
LAB_00039218:
  lVar6 = 1;
LAB_0003928c:
  FUN_00038f44(lVar6,lVar7,param_3,plVar1);
LAB_00039294:
  if (plVar3 != (longlong *)0x0) {
    plVar3 = (longlong *)plVar3[4];
  }
  bVar2 = false;
  plVar1 = plVar3;
  goto joined_r0x0003918f;
}

