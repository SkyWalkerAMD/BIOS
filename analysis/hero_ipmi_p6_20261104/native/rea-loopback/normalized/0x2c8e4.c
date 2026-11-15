undefined8 FUN_0002c8e4(char *param_1,longlong param_2)
{
  char cVar1;
  short sVar2;
  bool bVar3;
  longlong lVar4;
  longlong *plVar5;
  ushort uVar6;
  short *psVar7;
  uint *puVar8;
  short *psVar9;
  char *pcVar10;
  uint *puVar11;
  undefined *puVar12;
  char *pcVar13;
  bool bVar14;
  ushort local_res18;
  undefined2 local_res20;
  int local_138;
  longlong *local_130;
  int local_128;
  char *local_120;
  char *local_118;
  short local_108 [40];
  undefined4 local_b8 [4];
  short local_a8 [40];
  int local_58;
  uint local_54;
  int local_50;
  longlong local_48;
  undefined2 local_40;
  pcVar13 = (char *)0x0;
  cVar1 = *param_1;
  local_130 = (longlong *)0x0;
  local_118 = (char *)0x0;
  local_120 = (char *)0x0;
  local_res18 = 0;
  local_res20 = 0;
  local_128 = 0;
  local_138 = 0;
  bVar3 = false;
  if (cVar1 == '$') {
    local_res18 = *(ushort *)(param_1 + 0x12);
    local_130 = (longlong *)(param_1 + 2);
    local_res20 = *(undefined2 *)(param_1 + 0x14);
    pcVar10 = param_1 + 0x16;
    FUN_0010749e((undefined4 *)local_108,0x50,0);
    cVar1 = *pcVar10;
    psVar9 = local_108;
    for (uVar6 = 0; (local_118 = param_1, cVar1 != '\0' && (uVar6 < 0x28)); uVar6 = uVar6 + 1) {
      pcVar10 = pcVar10 + 1;
      *psVar9 = (short)cVar1;
      psVar9 = psVar9 + 1;
      cVar1 = *pcVar10;
    }
  }
  else if (cVar1 == '%') {
    local_res18 = *(ushort *)(param_1 + 2);
    local_130 = (longlong *)(param_1 + 4);
    FUN_000b07bc(local_108,0x28,(short *)&DAT_0016be88);
    local_138 = 0x2000;
  }
  else if (cVar1 == '&') {
    local_128 = *(int *)(param_1 + 0x14);
    local_130 = (longlong *)(param_1 + 4);
    local_res18 = *(ushort *)(param_1 + 2);
    local_138 = 0x1000;
    local_120 = param_1;
    if (0x2001e < *(uint *)(DAT_00180180 + 8)) {
      bVar3 = true;
      pcVar10 = param_1 + 0x1a;
      FUN_0010749e((undefined4 *)local_108,0x50,0);
      cVar1 = *pcVar10;
      psVar9 = local_108;
      for (uVar6 = 0; (cVar1 != '\0' && (uVar6 < 0x28)); uVar6 = uVar6 + 1) {
        pcVar10 = pcVar10 + 1;
        *psVar9 = (short)cVar1;
        psVar9 = psVar9 + 1;
        cVar1 = *pcVar10;
      }
      local_res20 = *(undefined2 *)(param_1 + 0x18);
    }
  }
  uVar6 = 0;
  pcVar10 = pcVar13;
  if (*DAT_00193658 != 0) {
    do {
      pcVar13 = (char *)((ulonglong)DAT_00193658[(ulonglong)uVar6 + 1] + DAT_00193670);
      if ((local_130 != (longlong *)0x0) &&
         (lVar4 = FUN_000b1b20(local_130,(longlong *)pcVar13,0x10), lVar4 == 0)) {
        cVar1 = *param_1;
        if (cVar1 == '$') {
          psVar9 = (short *)(pcVar13 + 0x10);
          psVar7 = local_108;
          sVar2 = local_108[0];
          while ((sVar2 != 0 && (sVar2 == *psVar9))) {
            psVar7 = psVar7 + 1;
            psVar9 = psVar9 + 1;
            sVar2 = *psVar7;
          }
          if (*psVar7 == *psVar9) {
            if (param_2 == *(longlong *)(pcVar13 + 0x70)) {
LAB_0002cbb9:
              pcVar10 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
            }
            else {
              if (((uVar6 == 0) || ((*(uint *)(pcVar13 + 0x68) & 0x1000) != 0)) ||
                 ((uVar6 < 0x3a && ((0x3ff800003fcfffeU >> ((ulonglong)uVar6 & 0x3f) & 1) != 0)))) {
LAB_0002cc7f:
                pcVar10 = IMAGE_DOS_HEADER_00000000.e_magic + 1;
                break;
              }
              if (*(longlong *)(pcVar13 + 0x70) == 0) {
                bVar14 = *(short *)(local_118 + 0x14) == *(short *)(pcVar13 + 0x78);
LAB_0002cc75:
                if (bVar14) {
                  *(longlong *)(pcVar13 + 0x70) = param_2;
                  goto LAB_0002cc7f;
                }
              }
            }
          }
        }
        else if (cVar1 == '%') {
          if (((*(uint *)(pcVar13 + 0x68) & 0x2000) != 0) && (*(int *)(pcVar13 + 0x68) == local_138)
             ) goto LAB_0002cc7f;
        }
        else if (cVar1 == '&') {
          if (bVar3) {
            psVar9 = (short *)(pcVar13 + 0x10);
            psVar7 = local_108;
            sVar2 = local_108[0];
            while ((sVar2 != 0 && (sVar2 == *psVar9))) {
              psVar7 = psVar7 + 1;
              psVar9 = psVar9 + 1;
              sVar2 = *psVar7;
            }
            if (*psVar7 == *psVar9) {
              if ((((param_2 == *(longlong *)(pcVar13 + 0x70)) || (uVar6 == 0)) ||
                  ((*(uint *)(pcVar13 + 0x68) & 0x1000) != 0)) ||
                 ((uVar6 < 0x3a && ((0x3ff800003fcfffeU >> ((ulonglong)uVar6 & 0x3f) & 1) != 0))))
              goto LAB_0002cc7f;
              if (*(longlong *)(pcVar13 + 0x70) == 0) {
                bVar14 = *(short *)(local_120 + 0x18) == *(short *)(pcVar13 + 0x78);
                goto LAB_0002cc75;
              }
            }
          }
          else if (((*(uint *)(pcVar13 + 0x68) & 0x1000) != 0) &&
                  (*(int *)(pcVar13 + 0x60) == local_128)) goto LAB_0002cbb9;
        }
        if (pcVar10 != (char *)0x0) break;
      }
      uVar6 = uVar6 + 1;
    } while ((uint)uVar6 < *DAT_00193658);
  }
  if ((*param_1 == '&') && (bVar3)) {
    puVar11 = &DAT_001936e0;
    puVar8 = &DAT_001936e0;
    if (DAT_001936f0 != 0) {
      do {
        if ((*puVar8 == (uint)local_res18) &&
           (lVar4 = DAT_001936f0, *(longlong *)(puVar8 + 2) == param_2)) goto LAB_0002cd2c;
        puVar8 = *(uint **)(puVar8 + 4);
      } while (*(longlong *)(puVar8 + 4) != 0);
    }
    if (DAT_001936e8 != 0) {
      puVar8 = puVar11;
      if (DAT_001936f0 != 0) {
        puVar11 = (uint *)&DAT_001936f0;
        do {
          puVar8 = *(uint **)puVar11;
          puVar11 = puVar8 + 4;
        } while (*(longlong *)puVar11 != 0);
      }
      puVar11 = (uint *)FUN_000014c8(0x18);
      *(uint **)(puVar8 + 4) = puVar11;
      if (puVar11 == (uint *)0x0) {
        return 0x8000000000000009;
      }
    }
    *puVar11 = (uint)local_res18;
    *(ushort *)(puVar11 + 1) = uVar6;
    *(longlong *)(puVar11 + 2) = param_2;
    lVar4 = DAT_001936f0;
LAB_0002cd2c:
    for (; lVar4 != 0; lVar4 = *(longlong *)(lVar4 + 0x10)) {
    }
  }
  if (pcVar10 == (char *)0x0) {
    FUN_0010749e(local_b8,0x80,0);
    local_54 = (uint)local_res18;
    (**(code **)(DAT_00180188 + 0x160))(local_b8,local_130);
    local_58 = local_128;
    local_50 = local_138;
    local_48 = param_2;
    if ((*param_1 == '$') || ((*param_1 == '&' && (bVar3)))) {
      FUN_000b07bc(local_a8,0x28,local_108);
      local_40 = local_res20;
    }
    FUN_0003048c(local_b8);
    goto LAB_0002cdfd;
  }
  *(uint *)(pcVar13 + 100) = (uint)local_res18;
  *(longlong *)(pcVar13 + 0x70) = param_2;
  *(int *)(pcVar13 + 0x68) = local_138;
  cVar1 = *param_1;
  if (cVar1 != '$') {
    if (cVar1 == '%') {
      FUN_000b07bc((short *)(pcVar13 + 0x10),0x28,local_108);
      goto LAB_0002cdfd;
    }
    if ((cVar1 != '&') || (!bVar3)) goto LAB_0002cdfd;
  }
  *(undefined2 *)(pcVar13 + 0x78) = local_res20;
LAB_0002cdfd:
  puVar12 = &DAT_001936c0;
  if (DAT_001936d0 != 0) {
    plVar5 = &DAT_001936d0;
    do {
      puVar12 = (undefined *)*plVar5;
      plVar5 = (longlong *)(puVar12 + 0x10);
    } while (*plVar5 != 0);
  }
  puVar8 = (uint *)FUN_000014c8(0x18);
  *(uint **)(puVar12 + 0x10) = puVar8;
  if (puVar8 == (uint *)0x0) {
    return 0x8000000000000009;
  }
  *puVar8 = (uint)local_res18;
  *(longlong *)(puVar8 + 2) = param_2;
  *(ushort *)(puVar8 + 1) = uVar6;
  return 0;
}
