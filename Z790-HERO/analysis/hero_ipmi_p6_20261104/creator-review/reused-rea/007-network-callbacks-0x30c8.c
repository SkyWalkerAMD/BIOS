
/* WARNING: Type propagation algorithm not settling */

undefined8 FUN_000030c8(undefined *param_1,undefined8 param_2,ulonglong param_3,short param_4)

{
  bool bVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  undefined *puVar5;
  undefined *puVar6;
  undefined2 uVar7;
  longlong *plVar8;
  undefined1 uVar9;
  undefined1 *puVar10;
  undefined1 local_res20 [8];
  longlong local_2a8;
  undefined4 local_29f;
  char local_29b [4];
  undefined4 local_297;
  byte local_293 [11];
  undefined1 local_288 [39];
  short local_261 [45];
  undefined4 local_207;
  undefined4 local_203;
  undefined4 local_1ff;
  undefined4 local_1fb;
  undefined4 local_1f7;
  undefined4 local_1f3;
  undefined4 local_1ef;
  undefined4 local_1eb;
  undefined2 local_1e7;
  
  if (7 < (ushort)(param_4 + 0xe0b1U)) {
    return 0x8000000000000003;
  }
  if (*(longlong *)(DAT_000153f8 + 8) == 0x1000) {
    return 0x8000000000000003;
  }
  if (*(longlong *)(DAT_000153f8 + 8) != 1) {
    return 0;
  }
  puVar10 = local_288;
  bVar1 = FUN_00009aac(1,param_2,param_3,puVar10);
  uVar9 = SUB81(puVar10,0);
  if (!bVar1) {
    return 0x8000000000000003;
  }
  if (param_4 == 0x1f4f) {
    lVar2 = FUN_00006080(&local_29f,local_261);
    if (-1 < lVar2) {
      return 0;
    }
    local_261[0] = 0x2e;
    local_261[1] = 0x2e;
    uVar7 = 0xf3;
    local_261[2] = 0x2e;
    local_261[3] = 0x2e;
    local_261[4] = 0;
    local_261[5] = 0;
    local_261[6] = 0;
    local_261[7] = 0;
    local_261[8] = 0;
    local_261[9] = 0;
    local_261[10] = 0;
    local_261[0xb] = 0;
    local_261[0xc] = 0;
    local_261[0xd] = 0;
    local_261[0xe] = 0;
  }
  else if (param_4 == 0x1f50) {
    lVar2 = FUN_00006080((undefined4 *)local_29b,local_261 + 0xf);
    if ((-1 < lVar2) && (lVar3 = local_2a8, local_29b[0] == -1)) goto LAB_000032a2;
    lVar2 = -0x7ffffffffffffffe;
    local_261[0xf] = 0x2e;
    local_261[0x10] = 0x2e;
    local_261[0x11] = 0x2e;
    local_261[0x12] = 0x2e;
    local_261[0x13] = 0;
    local_261[0x14] = 0;
    uVar7 = 0xf5;
    local_261[0x15] = 0;
    local_261[0x16] = 0;
    local_261[0x17] = 0;
    local_261[0x18] = 0;
    local_261[0x19] = 0;
    local_261[0x1a] = 0;
    local_261[0x1b] = 0;
    local_261[0x1c] = 0;
    local_261[0x1d] = 0;
  }
  else if (param_4 == 0x1f51) {
    lVar2 = FUN_00006080(&local_297,local_261 + 0x1e);
    if (-1 < lVar2) {
      return 0;
    }
    local_261[0x1e] = 0x30;
    local_261[0x1f] = 0x2e;
    uVar7 = 0xf6;
    local_261[0x20] = 0x30;
    local_261[0x21] = 0x2e;
    local_261[0x22] = 0x30;
    local_261[0x23] = 0x2e;
    local_261[0x24] = 0x30;
    local_261[0x25] = 0;
    local_261[0x26] = 0;
    local_261[0x27] = 0;
    local_261[0x28] = 0;
    local_261[0x29] = 0;
    local_261[0x2a] = 0;
    local_261[0x2b] = 0;
    local_261[0x2c] = 0;
  }
  else {
    if (param_4 != 0x1f52) {
      return 0x8000000000000003;
    }
    lVar2 = FUN_000061e4(local_293,(longlong)&local_207);
    if (-1 < lVar2) {
      return 0;
    }
    local_207 = 0x300030;
    local_1e7 = 0x30;
    uVar7 = 0xf7;
    local_203 = 0x30002d;
    local_1ff = 0x2d0030;
    local_1fb = 0x300030;
    local_1f7 = 0x30002d;
    local_1f3 = 0x2d0030;
    local_1ef = 0x300030;
    local_1eb = 0x30002d;
  }
  lVar3 = FUN_000097d0(param_1,uVar7,param_3,uVar9);
LAB_000032a2:
  if (lVar2 < 0) {
    plVar8 = &local_2a8;
    lVar2 = 0;
    local_2a8 = 0;
    puVar6 = &DAT_0000a380;
    lVar4 = (**(code **)(DAT_00015458 + 0x140))();
    if (-1 < lVar4) {
      lVar2 = 0xf9;
      puVar5 = (undefined *)FUN_000097d0(param_1,0xf9,(ulonglong)plVar8,uVar9);
      puVar6 = param_1;
      if ((lVar3 != 0) && (puVar5 != (undefined *)0x0)) {
        plVar8 = (longlong *)CONCAT71((int7)((ulonglong)plVar8 >> 8),1);
        (**(code **)(local_2a8 + 0x20))(puVar5,lVar3,plVar8,local_res20);
        lVar2 = DAT_00015458;
        (**(code **)(DAT_00015458 + 0x48))(lVar3);
        (**(code **)(DAT_00015458 + 0x48))();
        puVar6 = puVar5;
      }
    }
    bVar1 = FUN_00009ba8(puVar6,lVar2,(longlong)plVar8,local_288);
    if (!bVar1) {
      return 0x8000000000000003;
    }
  }
  return 0;
}

