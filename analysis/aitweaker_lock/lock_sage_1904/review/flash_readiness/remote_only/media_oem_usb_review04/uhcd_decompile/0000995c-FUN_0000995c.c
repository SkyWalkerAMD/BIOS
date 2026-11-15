
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_0000995c(undefined8 param_1,longlong param_2)

{
  byte bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined2 *puVar6;
  undefined8 uVar7;
  byte bVar8;
  ulonglong uVar9;
  undefined8 *local_res10;
  char local_38 [32];
  
  if ((((*(byte *)(param_2 + 0xa0) & 1) != 0) || ((*DAT_00010438 & 0x2000) == 0)) ||
     (((*DAT_00010438 & 0x4000) != 0 && (*(char *)(param_2 + 0x58) == '\x04')))) {
    bVar1 = *(byte *)((longlong)DAT_00010438 + 0x716);
    uVar9 = 1;
    if (1 < bVar1) {
      do {
        bVar8 = (byte)uVar9;
        if (uVar9 * 0x1c0 + *(longlong *)(DAT_00010458 + 0x42) == param_2) break;
        bVar8 = bVar8 + 1;
        uVar9 = (ulonglong)bVar8;
      } while (bVar8 < bVar1);
      if (bVar8 < bVar1) {
        (**(code **)(DAT_000104c0 + 0x168))(DAT_00010460,0x1f);
        puVar6 = DAT_00010460;
        *DAT_00010460 = 0xa27;
        *(byte *)((longlong)puVar6 + 3) = bVar8;
        *(undefined1 *)(puVar6 + 2) = 0;
        FUN_00003d5c();
        (**(code **)(DAT_000104c0 + 0x40))(4,0xa0,&local_res10);
        *local_res10 = 0x73616d75;
        local_res10[0xe] = param_2;
        local_res10[0x10] = param_1;
        local_res10[0x12] = param_2 + 0xb8;
        *(undefined1 *)(local_res10 + 0x13) = *(undefined1 *)(param_2 + 0x4c);
        (**(code **)(DAT_000104c0 + 0x40))(4,0x30,local_res10 + 0xd);
        *(undefined4 *)local_res10[0xd] = 0;
        *(undefined1 *)(local_res10[0xd] + 6) = 0;
        if (*(char *)(local_res10 + 0x13) == '\x02') {
          *(undefined1 *)(local_res10[0xd] + 7) = 1;
        }
        else {
          *(undefined1 *)(local_res10[0xd] + 7) = 0;
        }
        *(undefined1 *)(local_res10[0xd] + 8) = 0;
        *(uint *)(local_res10[0xd] + 0xc) = (uint)*(ushort *)(param_2 + 0x5e);
        *(undefined4 *)(local_res10[0xd] + 0x10) = 0;
        if ((*(byte *)(param_2 + 0xa0) & 8) == 0) {
          *(undefined1 *)(local_res10[0xd] + 4) = 0;
        }
        else {
          *(undefined1 *)(local_res10[0xd] + 4) = 1;
        }
        if ((((*(byte *)(param_2 + 0xa0) & 1) == 0) || (*(longlong *)(param_2 + 0x60) == 0)) ||
           (*(short *)(param_2 + 0x5e) == 0)) {
          *(undefined8 *)(local_res10[0xd] + 0x18) = 0;
          *(undefined1 *)(local_res10[0xd] + 5) = 0;
        }
        else {
          *(longlong *)(local_res10[0xd] + 0x18) = *(longlong *)(param_2 + 0x60) + -1;
          *(undefined1 *)(local_res10[0xd] + 5) = 1;
        }
        if (*(uint *)(DAT_000104b8 + 8) < 0x2001f) {
          local_res10[1] = 1;
        }
        else {
          local_res10[1] = 0x2001f;
          *(undefined4 *)(local_res10[0xd] + 0x28) = 1;
          *(undefined8 *)(local_res10[0xd] + 0x20) = 0;
          *(undefined4 *)(local_res10[0xd] + 0x2c) = *(undefined4 *)(local_res10[0xd] + 0xc);
        }
        uVar5 = uRam000000000000fa4c;
        uVar4 = uRam000000000000fa48;
        uVar3 = uRam000000000000fa44;
        uVar2 = _DAT_0000fa40;
        local_res10[2] = local_res10[0xd];
        local_res10[3] = &LAB_00003ce4;
        local_res10[4] = &LAB_0000a2d4;
        local_res10[5] = &LAB_0000a358;
        local_res10[6] = &LAB_00003ce4;
        *(undefined4 *)(local_res10 + 7) = uVar2;
        *(undefined4 *)((longlong)local_res10 + 0x3c) = uVar3;
        *(undefined4 *)(local_res10 + 8) = uVar4;
        *(undefined4 *)((longlong)local_res10 + 0x44) = uVar5;
        local_res10[9] = FUN_00009ce8;
        local_res10[10] = &LAB_00009d98;
        local_res10[0xb] = &LAB_00009e64;
        local_res10[0xc] = &LAB_00003cd8;
        *(ushort *)(local_res10 + 0xf) = (ushort)bVar8;
        *(undefined2 *)(local_res10 + 0x11) =
             *(undefined2 *)
              (*(longlong *)(DAT_00010568 + (longlong)(int)(*(byte *)(param_2 + 0xb) - 1) * 8) +
              0x2a);
        uVar7 = (**(code **)(DAT_000104c0 + 0x148))
                          (local_res10 + 0x10,&DAT_0000ebf0,local_res10 + 1,&DAT_0000ea10,
                           local_res10 + 7,0);
        FUN_0000d074(local_38,0x1e,(byte *)u_DetectUsbMass_0x_X_0x_X_0000fd08,
                     (ulonglong)*(ushort *)(param_2 + 6));
        FUN_0000d074(local_38,0x1e,(byte *)u_ConfigUsbMass_0x_X_0x_X_0000fd38,
                     (ulonglong)*(ushort *)(param_2 + 6));
        return uVar7;
      }
    }
  }
  return 0x8000000000000007;
}

