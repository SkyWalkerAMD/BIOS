
ulonglong FUN_0000af54(byte *param_1)

{
  byte bVar1;
  uint uVar2;
  undefined8 *puVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  undefined8 uVar6;
  short sVar7;
  int iVar8;
  char cVar9;
  char cVar10;
  char cVar11;
  undefined8 *local_38;
  ulonglong local_30;
  undefined8 local_28;
  undefined4 local_20;
  
  uVar5 = 0;
  cVar9 = '\x03';
  cVar11 = '\x03';
  cVar10 = *(char *)(DAT_0001b2c0 + 0x6ad);
  do {
    if (cVar10 == '\0') {
      return uVar5;
    }
    if ((param_1[0x7c] & 8) != 0) {
LAB_0000b0ca:
      if (cVar10 == '\0') {
        return uVar5;
      }
      uVar5 = FUN_0000b314(param_1);
      return uVar5 & 0xff;
    }
    puVar3 = (undefined8 *)FUN_00002f1c(1);
    if (puVar3 == (undefined8 *)0x0) {
      return 0xff;
    }
    local_28 = 0;
    local_20 = 0;
    *(undefined1 *)puVar3 = 0;
    bVar1 = 0xc;
    if (param_1[0x58] == 6) {
      bVar1 = 6;
    }
    local_30 = (ulonglong)bVar1;
    local_38 = puVar3;
    uVar4 = FUN_00009640((longlong)param_1,&local_38);
    uVar5 = uVar4 & 0xffffffff;
    FUN_000030f0(puVar3,1);
    if (((int)uVar4 == 0xff) || (param_1[0x59] < 2)) {
      uVar2 = FUN_0000ae3c((longlong)param_1);
      uVar5 = (ulonglong)uVar2;
    }
    if ((char)uVar5 == '\0') goto LAB_0000b0ca;
    sVar7 = (short)uVar5;
    if (sVar7 == 0x2806) {
      if (param_1[0x58] == 4) {
LAB_0000b02d:
        FUN_0000ac5c((longlong)param_1);
      }
LAB_0000b035:
      uVar6 = 100000;
    }
    else if (sVar7 == 0x3a02) {
      cVar9 = cVar9 + -1;
      if (cVar9 == '\0') {
        return uVar5;
      }
LAB_0000b04b:
      uVar6 = 20000;
    }
    else {
      iVar8 = (int)uVar5;
      if (iVar8 == 0x20402) goto LAB_0000b02d;
      if (sVar7 == 0x1103) goto LAB_0000b035;
      if (iVar8 != 0x10402) {
        if ((char)uVar5 == '\a') goto LAB_0000b0ca;
        if ((iVar8 - 2U & 0xfb) != 0) {
          return uVar5;
        }
      }
      if (iVar8 == 2) {
        cVar11 = cVar11 + -1;
        if (cVar11 == '\0') {
          return uVar5;
        }
        goto LAB_0000b04b;
      }
      uVar6 = 1000000;
    }
    (**(code **)(DAT_0001abe0 + 0xf8))(uVar6);
    cVar10 = cVar10 + -1;
  } while( true );
}

