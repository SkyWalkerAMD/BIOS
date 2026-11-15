
undefined8 FUN_00009a54(byte *param_1)

{
  uint uVar1;
  undefined8 in_RAX;
  undefined8 *puVar2;
  ulonglong uVar3;
  uint uVar4;
  undefined8 *local_28;
  undefined2 local_20;
  undefined6 uStack_1e;
  undefined2 local_18;
  undefined4 uStack_16;
  undefined2 uStack_12;
  undefined4 local_10;
  
  if ((*param_1 & 3) != 0) {
    puVar2 = (undefined8 *)FUN_00002f1c(1);
    in_RAX = 0;
    if (puVar2 != (undefined8 *)0x0) {
      *(undefined2 *)puVar2 = 0x109e;
      *(undefined4 *)((longlong)puVar2 + 10) = 0xc000000;
      uStack_12 = 0;
      local_10 = 0;
      *(undefined2 *)(DAT_0001b2c0 + 0x6ae) = 10000;
      local_20 = 0x8010;
      uStack_16 = 0xc;
      uStack_1e = (undefined6)*(undefined8 *)(DAT_0001ab98 + 0x62);
      local_18 = (undefined2)((ulonglong)*(undefined8 *)(DAT_0001ab98 + 0x62) >> 0x30);
      local_28 = puVar2;
      uVar3 = FUN_00009640((longlong)param_1,&local_28);
      *(undefined2 *)(DAT_0001b2c0 + 0x6ae) = 0;
      if ((int)uVar3 != 0) {
        uVar1 = *(uint *)(*(longlong *)(DAT_0001ab98 + 0x62) + 8);
        uVar4 = uVar1 & 0xff0000 | uVar1 >> 0x10;
        if (uVar4 >> 8 != 0 || ((uVar1 & 0xff00) != 0 || (uVar1 & 0xff) != 0)) {
          *(short *)(param_1 + 0x5e) = (short)(uVar4 >> 8);
          uVar1 = **(uint **)(DAT_0001ab98 + 0x62);
          *(ulonglong *)(param_1 + 0x60) =
               (((ulonglong)((uVar1 & 0xff00 | uVar1 << 0x10) << 8) << 8 |
                (ulonglong)uVar1 & 0xff0000) << 0x10 | (ulonglong)uVar1 & 0xffffffffff000000) << 8;
          uVar1 = *(uint *)(*(longlong *)(DAT_0001ab98 + 0x62) + 4);
          *(ulonglong *)(param_1 + 0x60) =
               *(ulonglong *)(param_1 + 0x60) |
               (ulonglong)((uVar1 & 0xff00 | uVar1 << 0x10) << 8) |
               ((ulonglong)uVar1 & 0xff0000 | (ulonglong)(uVar1 >> 0x10)) >> 8;
          return (((ulonglong)uVar1 & 0xff0000) >> 0x10) << 8;
        }
      }
      in_RAX = FUN_000030f0(puVar2,1);
    }
  }
  return CONCAT71((int7)((ulonglong)in_RAX >> 8),0xff);
}

