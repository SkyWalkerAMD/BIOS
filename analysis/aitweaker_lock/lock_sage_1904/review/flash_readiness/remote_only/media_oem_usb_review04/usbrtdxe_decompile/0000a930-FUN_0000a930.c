
uint FUN_0000a930(byte *param_1,byte param_2,longlong param_3)

{
  ushort uVar1;
  longlong lVar2;
  byte *pbVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  uint uVar7;
  ulonglong uVar8;
  uint uVar9;
  byte bVar10;
  byte *local_48;
  undefined1 local_40;
  undefined1 local_3f;
  longlong local_3e;
  uint local_36;
  undefined2 local_32;
  undefined2 local_30;
  
  uVar1 = *(ushort *)(param_3 + 0xd);
  bVar10 = 0;
  lVar2 = *(longlong *)(param_3 + 0x13);
  DAT_0001ab88 = 0;
  *(undefined4 *)(param_3 + 1) = 0;
  uVar9 = 0;
  pbVar6 = (byte *)FUN_00002f1c(1);
  if (pbVar6 == (byte *)0x0) {
    uVar4 = 0;
  }
  else {
    do {
      *pbVar6 = param_2;
      uVar8 = *(ulonglong *)(param_3 + 5);
      if (*(longlong *)(param_1 + 0x60) - (ulonglong)uVar1 < *(ulonglong *)(param_3 + 5)) {
        uVar8 = *(longlong *)(param_1 + 0x60) - (ulonglong)uVar1;
      }
      if ((param_1[0x74] == 4) && ((*DAT_0001b2c0 & 2) == 0)) {
        uVar8 = uVar8 + param_1[0x5c];
      }
      if (*(short *)(param_1 + 0x5e) != -1) {
        uVar4 = (uint)uVar8;
        if ((param_2 < 0x30) && ((0x850000000000U >> ((ulonglong)param_2 & 0x3f) & 1) != 0)) {
          *(uint *)(pbVar6 + 2) =
               (uVar4 & 0xff0000 | (uint)(uVar8 >> 0x10) & 0xffff) >> 8 |
               (uVar4 & 0xff00 | uVar4 << 0x10) << 8;
          *(ushort *)(pbVar6 + 7) = uVar1 * 0x100 + (uVar1 >> 8);
          local_40 = 0xc;
          if (param_1[0x58] == 6) {
            local_40 = 10;
          }
        }
        else {
          uVar7 = (uint)(uVar8 >> 0x20);
          *(uint *)(pbVar6 + 10) = (uVar1 & 0xff00) << 8 | (uint)uVar1 << 0x18;
          *(ulonglong *)(pbVar6 + 2) =
               (((ulonglong)((uVar4 << 0x10 | uVar4 & 0xff00) << 8) << 8 | uVar8 & 0xff0000) << 0x10
               | uVar8 & 0xff000000) << 8 | (ulonglong)((uVar7 << 0x10 | uVar7 & 0xff00) << 8) |
               (uVar8 >> 0x20 & 0xff0000 | uVar8 >> 0x30) >> 8;
          local_40 = 0x10;
        }
        uVar7 = 0;
        pbVar3 = DAT_0001b2c0;
        pbVar3[0x6ae] = 0;
        pbVar3[0x6af] = 0;
        if ((param_2 != 0x2f) && (param_2 != 0x8f)) {
          pbVar3 = DAT_0001b2c0;
          pbVar3[0x6ae] = 0x20;
          pbVar3[0x6af] = 0x4e;
          uVar7 = (uint)*(ushort *)(param_1 + 0x5e) * (uint)uVar1;
        }
        if ((param_2 == 0x2a) || (local_3f = 0x80, param_2 == 0x8a)) {
          local_3f = 0;
        }
        local_32 = *(undefined2 *)(param_3 + 0xf);
        local_30 = *(undefined2 *)(param_3 + 0x11);
        local_48 = pbVar6;
        local_3e = lVar2;
        local_36 = uVar7;
        uVar8 = FUN_00009640((longlong)param_1,&local_48);
        uVar4 = (uint)uVar8;
        if ((uVar4 != 0) && ((bVar10 != 0 || (uVar4 == uVar7)))) {
          if (0xffff < uVar4) {
            uVar4 = 0xffff;
          }
          if ((((param_1[0x74] == 4) && (param_2 == 0x28)) && (*(longlong *)(param_3 + 5) == 0)) &&
             ((*DAT_0001b2c0 & 2) == 0)) {
            *(undefined4 *)(lVar2 + 0x1c) = 0;
            if (((*(int *)(lVar2 + 3) == 0x65657246) && (*(int *)(lVar2 + 7) == 0x20534f44)) &&
               (*(int *)(lVar2 + 0x3a) != 0x20202032)) {
              *(short *)(lVar2 + 0x42) = *(short *)(lVar2 + 0x42) - (ushort)param_1[0x5c];
              *(short *)(lVar2 + 0x46) = *(short *)(lVar2 + 0x46) - (ushort)param_1[0x5c];
              *(short *)(lVar2 + 0x4a) = *(short *)(lVar2 + 0x4a) - (ushort)param_1[0x5c];
            }
            if (*(int *)(lVar2 + 0x52) == 0x33544146) {
              *(undefined1 *)(lVar2 + 0x40) = 0;
            }
            else {
              *(undefined1 *)(lVar2 + 0x24) = 0;
            }
          }
          break;
        }
        iVar5 = FUN_0000ae3c((longlong)param_1);
        *(int *)(param_3 + 1) = iVar5;
        uVar4 = uVar9;
        if ((char)iVar5 == '\a') break;
        if (((param_2 == 0x2f) || (param_2 == 0x8f)) && (iVar5 == 0)) {
          uVar4 = 0xffff;
          break;
        }
      }
      uVar8 = FUN_0000af54(param_1);
      *(int *)(param_3 + 1) = (int)uVar8;
      uVar4 = uVar9;
      if ((int)uVar8 != 0) break;
      FUN_00000300((undefined8 *)pbVar6,0x10);
      bVar10 = bVar10 + 1;
    } while (bVar10 < 2);
    FUN_000030f0((undefined8 *)pbVar6,1);
    uVar4 = uVar4 & 0xffff;
  }
  return uVar4;
}

