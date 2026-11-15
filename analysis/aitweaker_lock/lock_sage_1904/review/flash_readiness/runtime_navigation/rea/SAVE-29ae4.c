
ulonglong FUN_00029ae4(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  longlong lVar1;
  byte bVar2;
  longlong *plVar3;
  longlong lVar4;
  longlong *plVar5;
  uint *puVar6;
  ulonglong uVar7;
  
  plVar5 = (longlong *)0x0;
  bVar2 = 0;
  FUN_00029934(param_1,param_2,param_3);
  if ((DAT_000836e8 == 0) || (*(longlong *)(DAT_000836e8 + 8) == 0)) {
    uVar7 = 0x800000000000000e;
  }
  else {
    do {
      plVar3 = *(longlong **)(DAT_000836e8 + 8);
      if (plVar3 == (longlong *)0x0) break;
      if ((DAT_00093028 == 0) || (DAT_00093030 == 0)) {
        lVar4 = plVar3[1];
        puVar6 = (uint *)plVar3[2];
      }
      else {
        do {
          uVar7 = 0;
          if (DAT_00093030 != 0) {
            do {
              if (*(longlong *)(DAT_00093028 + uVar7 * 8) == *plVar3) goto LAB_00029b6b;
              uVar7 = uVar7 + 1;
            } while (uVar7 < DAT_00093030);
          }
          plVar3 = (longlong *)plVar3[5];
        } while (plVar3 != (longlong *)0x0);
LAB_00029b6b:
        if (plVar3 == (longlong *)0x0) {
          DAT_000836d8 = 0;
          DAT_000836db = 1;
          return ~-(ulonglong)bVar2 & 0x800000000000000e;
        }
        lVar4 = plVar3[1];
        bVar2 = 1;
        puVar6 = (uint *)plVar3[2];
        plVar5 = plVar3;
      }
      lVar1 = *plVar3;
      if (lVar4 == 1) {
        if ((DAT_000836da != '\0') && (DAT_000836f8 != 0)) {
          FUN_0002c2c4();
        }
        FUN_0002bb60(lVar1,puVar6);
      }
      else if (lVar4 == 2) {
        if ((DAT_000836f0 == '\0') || (DAT_000836f8 != lVar1)) {
          if ((DAT_000836da != '\0') && (DAT_000836f8 != 0)) {
            FUN_0002c2c4();
          }
          lVar4 = FUN_0002bdd4(lVar1);
          if (lVar4 == 0) {
            DAT_000836da = '\x01';
            DAT_000836f8 = lVar1;
          }
          DAT_000836f0 = '\x01';
        }
      }
      else if (lVar4 == 8) {
        FUN_0002c10c(lVar1,puVar6);
        DAT_000836da = '\0';
        FUN_0002c2c4();
        DAT_000836f0 = '\0';
      }
      if (((DAT_00093028 == 0) || (DAT_00093030 == 0)) || (plVar5 == (longlong *)0x0)) {
        FUN_000296b8(*(longlong *)(DAT_000836e8 + 8));
      }
      else {
        FUN_000296b8((longlong)plVar5);
        plVar5 = (longlong *)0x0;
      }
    } while (DAT_000836e8 != 0);
    uVar7 = 0;
  }
  DAT_000836d8 = 0;
  DAT_000836db = 1;
  return uVar7;
}

