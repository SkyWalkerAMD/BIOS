
undefined4 FUN_00013c74(uint param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  uint uVar5;
  uint uVar6;
  char cVar7;
  int iVar8;
  uint *puVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint *puVar14;
  undefined4 local_b0;
  uint local_ac;
  uint local_a8 [33];
  
  iVar1 = DAT_00014044;
  iVar13 = DAT_00014040;
  if (param_1 == 0xffffffff) {
    return 1;
  }
  if (param_2 < *(int *)(DAT_00014040 + 0x130)) {
    iVar11 = *(int *)(DAT_00014044 + param_2 * 4 + 0x10);
    *(char *)(iVar11 + 0x17) = (char)param_2;
    if (*(char *)(iVar11 + 0x29) == '(') {
      uVar10 = (uint)(*(ushort *)(iVar11 + 0x30) >> 8) | (*(ushort *)(iVar11 + 0x30) & 0xff) << 8;
      uVar5 = ((uint)*(byte *)(iVar11 + 0x21) << 8 | (uint)*(byte *)(iVar11 + 0x22) << 0x10 |
              (uint)*(byte *)(iVar11 + 0x23) << 0x18) >> 9;
      if (uVar5 != uVar10) {
        uVar6 = uVar5;
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014054,DAT_00014050,DAT_0001404c,uVar5,uVar10);
        if (*(int *)(iVar13 + 0x130) <= param_2) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00014084,DAT_00014050,DAT_00014080,uVar6,uVar10);
          goto LAB_00013f7c;
        }
        uVar6 = DAT_00014058 & uVar5 << 8;
        *(char *)(iVar11 + 0x30) = (char)(uVar5 >> 8);
        uVar10 = (uVar6 & 0xffff) >> 8 | uVar5 & 0xff00;
        *(char *)(iVar11 + 0x31) = (char)(uVar6 >> 8);
      }
      if (0x100 < uVar10) {
        uVar5 = 0x100;
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00014060,DAT_00014050,DAT_0001405c,uVar10,0x100);
        if (*(int *)(iVar13 + 0x130) <= param_2) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00014084,DAT_00014050,DAT_0001408c,uVar10,uVar5);
          uVar6 = uVar10;
          uVar10 = uVar5;
LAB_00013f7c:
          if (*(int *)(iVar13 + 0x130) <= param_2) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00014088,DAT_00014050,0x164,uVar6,uVar10);
            return 0;
          }
          cVar7 = '\0';
          iVar13 = *(int *)(iVar1 + param_2 * 4);
          *(undefined1 *)(iVar13 + 0xc) = 0x1d;
          *(undefined1 *)(iVar13 + 0x13) = 0x80;
          *(undefined1 *)(iVar13 + 0x35) = 1;
          *(undefined1 *)(iVar13 + 0x36) = 5;
          *(undefined1 *)(iVar13 + 0x37) = 0x26;
          *(undefined1 *)(iVar13 + 0x38) = 0;
          *(undefined1 *)(iVar13 + 0x39) = 0;
          *(undefined1 *)(iVar13 + 0x3a) = 0;
          *(undefined1 *)(iVar13 + 0x3b) = 0;
          *(undefined1 *)(iVar13 + 0x3c) = 0;
          *(undefined1 *)(iVar13 + 0xd) = 0;
          *(undefined1 *)(iVar13 + 0xe) = 0;
          *(undefined1 *)(iVar13 + 0xf) = 0;
          pcVar4 = (char *)(iVar13 + -1);
          do {
            pcVar4 = pcVar4 + 1;
            cVar7 = cVar7 + *pcVar4;
          } while ((char *)(iVar13 + 0x1f) != pcVar4);
          *(char *)(iVar13 + 0xb) = -cVar7;
          return 0;
        }
        *(undefined1 *)(iVar11 + 0x31) = 0;
        *(undefined1 *)(iVar11 + 0x30) = 1;
      }
    }
    iVar13 = 0;
    uVar10 = param_1 + 0x1f;
    if (-1 < (int)param_1) {
      uVar10 = param_1;
    }
    uVar5 = param_1 & 0x1f;
    if (-1 < (int)-param_1) {
      uVar5 = -(-param_1 & 0x1f);
    }
    iVar8 = *(int *)(iVar11 + 0xc) + 0x20;
    uVar5 = 1 << (uVar5 & 0xff);
    iVar1 = (int)uVar10 >> 5;
    iVar12 = 0;
    do {
      puVar14 = &local_ac;
      puVar9 = puVar14;
      do {
        puVar9 = puVar9 + 1;
        *puVar9 = 0;
      } while (puVar9 != local_a8 + 0x1f);
      local_a8[iVar1] = local_a8[iVar1] | uVar5;
      local_b0 = 5;
      local_ac = 0;
      iVar2 = sigwrap_select(param_1 + 1,0,local_a8,0,&local_b0);
      if (iVar2 < 1) {
        pcVar4 = DAT_0001406c;
        if (iVar2 != 0) {
          pcVar4 = DAT_00014070;
        }
        puts(pcVar4);
        goto LAB_00013f04;
      }
      if ((uVar5 & local_a8[iVar1]) != 0) {
        do {
          puVar14 = puVar14 + 1;
          *puVar14 = 0;
        } while (puVar14 != local_a8 + 0x1f);
        iVar13 = sigwrap_send(param_1,iVar11 + iVar12,iVar8 - iVar12,0x4000);
        if (iVar13 == -1) {
          piVar3 = __errno_location();
          pcVar4 = strerror(*piVar3);
          printf(DAT_00014048,pcVar4);
          goto LAB_00013f04;
        }
      }
      iVar12 = iVar12 + iVar13;
    } while (iVar8 != iVar12);
    if (iVar8 != -1) {
      return 0;
    }
LAB_00013f04:
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00014078,DAT_00014050,DAT_00014074);
    iVar13 = FUN_00013770(param_2);
    if (iVar13 != 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001407c,DAT_00014050,0x1e0);
      return 1;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00014068,DAT_00014050,DAT_00014064);
  }
  return 1;
}

