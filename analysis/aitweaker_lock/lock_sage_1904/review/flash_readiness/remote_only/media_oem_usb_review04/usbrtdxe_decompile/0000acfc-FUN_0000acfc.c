
undefined1 FUN_0000acfc(longlong param_1,longlong param_2)

{
  ushort uVar1;
  ushort uVar2;
  longlong lVar3;
  int iVar4;
  undefined8 *puVar5;
  ulonglong uVar6;
  undefined1 uVar7;
  undefined8 *local_28;
  undefined1 local_20;
  undefined1 uStack_1f;
  undefined6 uStack_1e;
  undefined2 local_18;
  undefined4 uStack_16;
  undefined2 uStack_12;
  undefined4 local_10;
  
  uVar7 = 0xff;
  puVar5 = (undefined8 *)FUN_00002f1c(1);
  if (puVar5 != (undefined8 *)0x0) {
    uStack_12 = 0;
    local_10 = 0;
    *(undefined1 *)puVar5 = 0x5a;
    *(undefined2 *)((longlong)puVar5 + 7) = 0x2800;
    *(undefined1 *)((longlong)puVar5 + 2) = 5;
    uStack_1f = 0x80;
    local_20 = 0xc;
    if (*(char *)(param_1 + 0x58) == '\x06') {
      local_20 = 10;
    }
    uStack_16 = 0x28;
    uStack_1e = (undefined6)*(undefined8 *)(DAT_0001ab98 + 0x62);
    local_18 = (undefined2)((ulonglong)*(undefined8 *)(DAT_0001ab98 + 0x62) >> 0x30);
    local_28 = puVar5;
    uVar6 = FUN_00009640(param_1,&local_28);
    if ((int)uVar6 == 0) {
      FUN_0000ae3c(param_1);
    }
    else {
      lVar3 = *(longlong *)(DAT_0001ab98 + 0x62);
      uVar6 = (ulonglong)*(ushort *)(lVar3 + 6);
      *(undefined1 *)(param_2 + 0xb) = *(undefined1 *)(lVar3 + 2);
      if (*(char *)(uVar6 + 8 + lVar3) == '\x05') {
        uVar1 = *(ushort *)(uVar6 + 0xe + lVar3);
        *(undefined1 *)(param_2 + 5) = *(undefined1 *)(uVar6 + 0xc + lVar3);
        uVar7 = *(undefined1 *)(uVar6 + 0xd + lVar3);
        uVar2 = *(ushort *)(uVar6 + 0x10 + lVar3);
        *(ushort *)(param_2 + 9) = uVar1 * 0x100 + (uVar1 >> 8);
        *(undefined1 *)(param_2 + 8) = uVar7;
        *(ushort *)(param_2 + 6) = uVar2 * 0x100 + (uVar2 >> 8);
        uVar7 = 0;
      }
      iVar4 = FUN_0000ae3c(param_1);
      *(int *)(param_2 + 1) = iVar4;
    }
    FUN_000030f0(puVar5,1);
  }
  return uVar7;
}

