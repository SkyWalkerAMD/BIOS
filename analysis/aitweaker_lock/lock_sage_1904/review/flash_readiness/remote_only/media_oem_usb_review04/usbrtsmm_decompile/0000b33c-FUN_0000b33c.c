
undefined8 FUN_0000b33c(longlong param_1)

{
  ushort uVar1;
  undefined8 *puVar2;
  char *pcVar3;
  ulonglong uVar4;
  undefined8 uVar5;
  uint uVar6;
  undefined8 *local_38;
  undefined1 local_30;
  undefined1 uStack_2f;
  undefined6 uStack_2e;
  undefined2 local_28;
  undefined4 uStack_26;
  undefined2 uStack_22;
  undefined4 local_20;
  
  puVar2 = (undefined8 *)FUN_00004150(1);
  uVar5 = 0;
  if (puVar2 != (undefined8 *)0x0) {
    pcVar3 = (char *)FUN_00004150(8);
    uVar5 = 0;
    if (pcVar3 != (char *)0x0) {
      uStack_22 = 0;
      *(undefined2 *)((longlong)puVar2 + 7) = 0xfc00;
      *(undefined1 *)puVar2 = 0x23;
      local_20 = 0;
      local_30 = 0xc;
      if (*(char *)(param_1 + 0x58) == '\x06') {
        local_30 = 10;
      }
      uStack_2f = 0x80;
      uStack_2e = SUB86(pcVar3,0);
      local_28 = (undefined2)((ulonglong)pcVar3 >> 0x30);
      uStack_26 = 0xfc;
      local_38 = puVar2;
      uVar4 = FUN_0000abf0(param_1,&local_38);
      if ((((0xb < (uint)uVar4) && (*pcVar3 == '\0')) && (pcVar3[1] == '\0')) &&
         (((pcVar3[2] == '\0' && (7 < (byte)pcVar3[3])) &&
          (uVar1 = *(ushort *)(pcVar3 + 10), uVar1 != 0)))) {
        *(ushort *)(param_1 + 0x5e) = uVar1 * 0x100 + (uVar1 >> 8);
        uVar6 = *(uint *)(pcVar3 + 4);
        if (uVar6 != 0) {
          uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
          *(ulonglong *)(param_1 + 0x60) = (ulonglong)uVar6;
          if (uVar6 == 0xb40) {
            *(undefined4 *)(param_1 + 0x6c) = 0x20050;
            *(undefined2 *)(param_1 + 0x68) = 2;
            *(undefined2 *)(param_1 + 0x72) = 0x50;
            *(undefined1 *)(param_1 + 0x6a) = 0x12;
            *(undefined1 *)(param_1 + 0x70) = 0x12;
            *(undefined1 *)(param_1 + 0x76) = 0x94;
          }
          FUN_00004324((undefined8 *)pcVar3,8);
          uVar4 = FUN_00004324(puVar2,1);
          return uVar4 & 0xffffffffffffff00;
        }
      }
      FUN_00004324((undefined8 *)pcVar3,8);
      uVar5 = FUN_00004324(puVar2,1);
    }
  }
  return CONCAT71((int7)((ulonglong)uVar5 >> 8),0xff);
}

