
undefined8 FUN_00009bd0(byte *param_1)

{
  undefined8 in_RAX;
  ulonglong uVar1;
  undefined8 *puVar2;
  undefined8 uVar3;
  uint uVar4;
  uint uVar5;
  undefined1 uVar6;
  undefined8 *local_28;
  undefined1 local_20;
  undefined1 uStack_1f;
  undefined6 uStack_1e;
  undefined2 local_18;
  undefined4 uStack_16;
  undefined2 uStack_12;
  undefined4 local_10;
  
  if ((*param_1 & 3) != 0) {
    if ((*(ulonglong *)(param_1 + 0x60) & 0xffffffff00000000) != 0) {
LAB_00009c03:
      uVar1 = FUN_00009a54(param_1);
      return uVar1 & 0xffffffffffffff00;
    }
    puVar2 = (undefined8 *)FUN_00002f1c(1);
    uVar6 = 0;
    in_RAX = 0;
    if (puVar2 != (undefined8 *)0x0) {
      *(undefined1 *)puVar2 = 0x25;
      uStack_12 = 0;
      local_10 = 0;
      *(undefined2 *)(DAT_0001b2c0 + 0x6ae) = 10000;
      local_20 = 0xc;
      if (param_1[0x58] == 6) {
        local_20 = 10;
      }
      uStack_1f = 0x80;
      uStack_16 = 8;
      uStack_1e = (undefined6)*(undefined8 *)(DAT_0001ab98 + 0x62);
      local_18 = (undefined2)((ulonglong)*(undefined8 *)(DAT_0001ab98 + 0x62) >> 0x30);
      local_28 = puVar2;
      uVar1 = FUN_00009640((longlong)param_1,&local_28);
      *(undefined2 *)(DAT_0001b2c0 + 0x6ae) = 0;
      if ((int)uVar1 != 0) {
        if (**(int **)(DAT_0001ab98 + 0x62) == -1) {
          FUN_000030f0(puVar2,1);
          goto LAB_00009c03;
        }
        uVar4 = (*(int **)(DAT_0001ab98 + 0x62))[1];
        uVar5 = uVar4 & 0xff0000 | uVar4 >> 0x10;
        if (uVar5 >> 8 != 0 || ((uVar4 & 0xff00) != 0 || (uVar4 & 0xff) != 0)) {
          *(short *)(param_1 + 0x5e) = (short)(uVar5 >> 8);
          uVar4 = **(uint **)(DAT_0001ab98 + 0x62);
          uVar4 = (uVar4 & 0xff0000 | uVar4 >> 0x10) >> 8 | (uVar4 & 0xff00 | uVar4 << 0x10) << 8;
          if (uVar4 == 0) {
            uVar6 = 0xff;
          }
          else {
            *(ulonglong *)(param_1 + 0x60) = (ulonglong)(uVar4 + 1);
          }
          uVar3 = FUN_000030f0(puVar2,1);
          return CONCAT71((int7)((ulonglong)uVar3 >> 8),uVar6);
        }
      }
      in_RAX = FUN_000030f0(puVar2,1);
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),0xff);
}

