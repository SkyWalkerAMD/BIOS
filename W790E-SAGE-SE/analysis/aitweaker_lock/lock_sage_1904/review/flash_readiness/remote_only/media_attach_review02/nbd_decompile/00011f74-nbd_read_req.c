
undefined4 nbd_read_req(int param_1)

{
  ushort uVar1;
  undefined1 uVar2;
  uint *puVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  undefined4 local_54;
  undefined4 local_50;
  uint local_4c;
  uint local_48;
  uint local_44;
  undefined4 local_40;
  ushort uStack_3e;
  uint local_3c;
  uint local_38;
  uint local_34;
  uint local_30;
  uint local_2c;
  undefined1 uVar3;
  undefined1 uVar4;
  undefined1 uVar5;
  undefined1 uVar6;
  
  uVar10 = DAT_000125b8;
  uVar9 = DAT_000125b4;
  uVar8 = DAT_000125b0;
  uVar12 = DAT_000125ac;
  puVar7 = DAT_000125a8;
  while( true ) {
    local_44 = 0;
    local_40 = 0;
    local_3c = 0;
    local_38 = 0;
    local_34 = 0;
    local_30 = 0;
    local_2c = 0;
    iVar11 = FUN_000110dc(*(undefined4 *)(param_1 + 8),&local_44,0x1c);
    if (iVar11 != 0) {
      if ((*puVar7 & 1) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut
                  (0x87,DAT_000125dc,DAT_000125b4,0x1fc,*(undefined4 *)(param_1 + 0x14));
        return 0xffffffff;
      }
      return 0xffffffff;
    }
    uVar14 = (local_44 ^ (local_44 >> 0x10 | local_44 << 0x10)) >> 8 & 0xffff00ff ^
             (local_44 >> 8 | local_44 << 0x18);
    if (uVar14 != uVar12) {
      if ((*puVar7 & 2) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000125e4,DAT_000125b4,DAT_000125e0,uVar14,uVar12);
        return 0xffffffff;
      }
      return 0xffffffff;
    }
    uVar1 = uStack_3e >> 8 | uStack_3e << 8;
    uVar2 = (undefined1)(local_2c >> 0x10);
    uVar3 = (undefined1)(local_34 >> 0x10);
    uVar4 = (undefined1)(local_30 >> 0x10);
    uVar5 = (undefined1)(local_3c >> 0x10);
    uVar6 = (undefined1)(local_38 >> 0x10);
    if (uVar1 == 1) break;
    if (uVar1 == 0) {
      uVar17 = (local_2c ^ (local_2c >> 0x10 | local_2c << 0x10)) >> 8 & 0xffff00ff ^ local_2c >> 8;
      uVar14 = (local_30 ^ (local_30 >> 0x10 | local_30 << 0x10)) >> 8 & 0xffff00ff ^ local_30 >> 8;
      uVar16 = *puVar7;
      uVar15 = (local_38 ^ (local_38 >> 0x10 | local_38 << 0x10)) >> 8 & 0xffff00ff ^ local_38 >> 8;
      uVar12 = (local_34 ^ (local_34 >> 0x10 | local_34 << 0x10)) >> 8 & 0xffff00ff ^ local_34 >> 8;
      *(undefined1 *)(param_1 + 0x41) = uVar2;
      *(char *)(param_1 + 0x42) = (char)(uVar17 >> 0x10);
      *(char *)(param_1 + 0x43) = (char)local_2c;
      *(undefined1 *)(param_1 + 0x35) = uVar3;
      *(char *)(param_1 + 0x36) = (char)(uVar12 >> 0x10);
      uVar13 = (local_3c ^ (local_3c >> 0x10 | local_3c << 0x10)) >> 8 & 0xffff00ff ^ local_3c >> 8;
      *(char *)(param_1 + 0x37) = (char)local_34;
      *(undefined1 *)(param_1 + 0x31) = uVar4;
      *(char *)(param_1 + 0x32) = (char)(uVar14 >> 0x10);
      *(char *)(param_1 + 0x33) = (char)local_30;
      *(undefined1 *)(param_1 + 0x2d) = uVar5;
      *(char *)(param_1 + 0x2e) = (char)(uVar13 >> 0x10);
      *(char *)(param_1 + 0x2f) = (char)local_3c;
      *(undefined1 *)(param_1 + 0x29) = uVar6;
      *(undefined1 *)(param_1 + 0x46) = 0;
      *(undefined1 *)(param_1 + 0x47) = 0;
      *(char *)(param_1 + 0x40) = (char)uVar17;
      *(char *)(param_1 + 0x34) = (char)uVar12;
      *(char *)(param_1 + 0x30) = (char)uVar14;
      *(char *)(param_1 + 0x2c) = (char)uVar13;
      *(char *)(param_1 + 0x28) = (char)uVar15;
      *(char *)(param_1 + 0x2a) = (char)(uVar15 >> 0x10);
      *(char *)(param_1 + 0x2b) = (char)local_38;
      if ((uVar16 & 2) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut
                  (0x87,DAT_000125d8,DAT_000125b4,DAT_000125d4,*(undefined4 *)(param_1 + 0x14));
        return 0;
      }
      return 0;
    }
    if (uVar1 == 2) {
      if ((*puVar7 & 2) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut
                  (0x87,DAT_000125d0,DAT_000125b4,DAT_000125cc,*(undefined4 *)(param_1 + 0x14));
        return 0xffffffff;
      }
      return 0xffffffff;
    }
    if ((*puVar7 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut
                (0x87,DAT_000125c8,uVar9,uVar8,uVar1,*(undefined4 *)(param_1 + 0x14));
    }
    local_50 = 0x16000000;
    local_4c = local_3c;
    local_54 = uVar10;
    local_48 = local_38;
    iVar11 = FUN_0001119c(*(undefined4 *)(param_1 + 8),&local_54,0x10);
    if (iVar11 != 0) {
      if ((*puVar7 & 1) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut
                  (0x87,DAT_000125c0,DAT_000125b4,DAT_000125bc,*(undefined4 *)(param_1 + 0x14));
      }
      return 0xffffffff;
    }
  }
  uVar13 = (local_2c ^ (local_2c >> 0x10 | local_2c << 0x10)) >> 8 & 0xffff00ff ^ local_2c >> 8;
  uVar12 = (local_34 ^ (local_34 >> 0x10 | local_34 << 0x10)) >> 8 & 0xffff00ff ^ local_34 >> 8;
  *(char *)(param_1 + 0x46) = (char)((uint)local_40 >> 0x18);
  uVar14 = (local_30 ^ (local_30 >> 0x10 | local_30 << 0x10)) >> 8 & 0xffff00ff ^ local_30 >> 8;
  *(undefined1 *)(param_1 + 0x41) = uVar2;
  *(char *)(param_1 + 0x42) = (char)(uVar13 >> 0x10);
  *(char *)(param_1 + 0x43) = (char)local_2c;
  uVar16 = (local_3c ^ (local_3c >> 0x10 | local_3c << 0x10)) >> 8 & 0xffff00ff ^ local_3c >> 8;
  *(undefined1 *)(param_1 + 0x35) = uVar3;
  *(char *)(param_1 + 0x36) = (char)(uVar12 >> 0x10);
  *(undefined1 *)(param_1 + 0x31) = uVar4;
  uVar15 = (local_38 ^ (local_38 >> 0x10 | local_38 << 0x10)) >> 8 & 0xffff00ff ^ local_38 >> 8;
  *(char *)(param_1 + 0x34) = (char)uVar12;
  *(char *)(param_1 + 0x30) = (char)uVar14;
  *(char *)(param_1 + 0x32) = (char)(uVar14 >> 0x10);
  *(char *)(param_1 + 0x37) = (char)local_34;
  *(char *)(param_1 + 0x33) = (char)local_30;
  *(char *)(param_1 + 0x2f) = (char)local_3c;
  *(undefined1 *)(param_1 + 0x2d) = uVar5;
  *(char *)(param_1 + 0x2e) = (char)(uVar16 >> 0x10);
  *(char *)(param_1 + 0x28) = (char)uVar15;
  *(char *)(param_1 + 0x2b) = (char)local_38;
  *(char *)(param_1 + 0x40) = (char)uVar13;
  *(char *)(param_1 + 0x2c) = (char)uVar16;
  *(char *)(param_1 + 0x2a) = (char)(uVar15 >> 0x10);
  *(undefined1 *)(param_1 + 0x47) = 0;
  *(undefined1 *)(param_1 + 0x29) = uVar6;
  iVar11 = FUN_000110dc(CONCAT13(*(undefined1 *)(param_1 + 0xb),
                                 CONCAT12(*(undefined1 *)(param_1 + 10),
                                          CONCAT11(*(undefined1 *)(param_1 + 9),
                                                   *(undefined1 *)(param_1 + 8)))),
                        CONCAT13(*(undefined1 *)(param_1 + 0x4b),
                                 CONCAT12(*(undefined1 *)(param_1 + 0x4a),
                                          *(undefined2 *)(param_1 + 0x48))));
  if (iVar11 == 0) {
    if ((*puVar7 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut
                (0x87,DAT_000125c4,DAT_000125b4,0x220,*(undefined4 *)(param_1 + 0x14));
      return 0;
    }
    return 0;
  }
  if ((*puVar7 & 2) != 0) {
    IDBG_LINUXAPP_Runtime_DbgOut
              (0x87,DAT_000125ec,DAT_000125b4,DAT_000125e8,*(undefined4 *)(param_1 + 0x14));
    return 0xffffffff;
  }
  return 0xffffffff;
}

