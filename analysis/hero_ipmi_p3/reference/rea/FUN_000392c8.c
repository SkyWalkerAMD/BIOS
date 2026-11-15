
ulonglong FUN_000392c8(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  ulonglong uVar1;
  byte bVar2;
  ulonglong *puVar3;
  ulonglong *puVar4;
  uint *puVar5;
  ulonglong uVar6;
  
  puVar4 = (ulonglong *)0x0;
  bVar2 = 0;
  FUN_00039118(param_1,param_2,param_3);
  if ((DAT_0018f1f8 == 0) || (*(longlong *)(DAT_0018f1f8 + 8) == 0)) {
    uVar6 = 0x800000000000000e;
  }
  else {
    do {
      puVar3 = *(ulonglong **)(DAT_0018f1f8 + 8);
      if (puVar3 == (ulonglong *)0x0) break;
      if ((DAT_00193728 == 0) || (DAT_00193730 == 0)) {
        uVar6 = puVar3[1];
        puVar5 = (uint *)puVar3[2];
      }
      else {
        do {
          uVar6 = 0;
          if (DAT_00193730 != 0) {
            do {
              if (*(ulonglong *)(DAT_00193728 + uVar6 * 8) == *puVar3) goto LAB_0003934f;
              uVar6 = uVar6 + 1;
            } while (uVar6 < DAT_00193730);
          }
          puVar3 = (ulonglong *)puVar3[5];
        } while (puVar3 != (ulonglong *)0x0);
LAB_0003934f:
        if (puVar3 == (ulonglong *)0x0) {
          DAT_0018f1d8 = 0;
          DAT_0018f1e8 = 1;
          return ~-(ulonglong)bVar2 & 0x800000000000000e;
        }
        uVar6 = puVar3[1];
        bVar2 = 1;
        puVar5 = (uint *)puVar3[2];
        puVar4 = puVar3;
      }
      uVar1 = *puVar3;
      if (uVar6 == 1) {
        if ((DAT_0018f1da != '\0') && (DAT_0018f1e0 != 0)) {
          FUN_000343e4();
        }
        FUN_00033c14(uVar1,puVar5);
      }
      else if (uVar6 == 2) {
        if ((DAT_0018f200 == '\0') || (DAT_0018f1e0 != uVar1)) {
          if ((DAT_0018f1da != '\0') && (DAT_0018f1e0 != 0)) {
            FUN_000343e4();
          }
          uVar6 = FUN_00033e74(uVar1);
          if (uVar6 == 0) {
            DAT_0018f1da = '\x01';
            DAT_0018f1e0 = uVar1;
          }
          DAT_0018f200 = '\x01';
        }
      }
      else if (uVar6 == 8) {
        FUN_00034238(uVar1,puVar5);
        DAT_0018f1da = '\0';
        FUN_000343e4();
        DAT_0018f200 = '\0';
      }
      if (((DAT_00193728 == 0) || (DAT_00193730 == 0)) || (puVar4 == (ulonglong *)0x0)) {
        FUN_00038e9c(*(longlong *)(DAT_0018f1f8 + 8));
      }
      else {
        FUN_00038e9c((longlong)puVar4);
        puVar4 = (ulonglong *)0x0;
      }
    } while (DAT_0018f1f8 != 0);
    uVar6 = 0;
  }
  DAT_0018f1d8 = 0;
  DAT_0018f1e8 = 1;
  return uVar6;
}

