
void FUN_0006c12c(longlong *param_1,longlong *param_2,longlong param_3,char param_4)

{
  int iVar1;
  uint uVar2;
  bool bVar3;
  short sVar4;
  ushort uVar5;
  undefined4 uVar6;
  byte *pbVar7;
  short *psVar8;
  undefined8 *puVar9;
  byte *pbVar10;
  ulonglong uVar11;
  byte *pbVar12;
  char *pcVar13;
  byte **ppbVar14;
  byte **ppbVar15;
  longlong lVar16;
  longlong lVar17;
  longlong lVar18;
  byte *pbVar19;
  ushort uVar20;
  longlong local_res18;
  char local_res20;
  ushort local_58;
  ushort local_54 [2];
  byte *local_50;
  char *local_48 [2];
  
  local_54[0] = 0;
  local_58 = 0;
  local_res18 = param_3;
  local_res20 = param_4;
  if ((*(byte *)(param_3 + 0x60) & 8) != 0) {
    FUN_00028728(*param_2,0xfffe,param_3);
  }
  uVar6 = FUN_00028250(param_2);
  local_50 = (byte *)CONCAT44(local_50._4_4_,uVar6);
  FUN_0002847c((longlong)param_2,(uint *)&local_50,(undefined8 *)0x0);
  uVar2 = (uint)local_50;
  ppbVar14 = (byte **)((ulonglong)local_50 & 0xffffffff);
  if ((uint)local_50 == 4) {
    FUN_0001b74c(4);
  }
  lVar18 = (ulonglong)*(uint *)(DAT_001937f0 + 4 + (longlong)ppbVar14 * 4) + DAT_001937f0;
  pbVar7 = (byte *)FUN_000014c8(0x28);
  if (pbVar7 != (byte *)0x0) {
    FUN_000b07bc((short *)pbVar7,0x14,u_PlatformLangCodes_0016c160);
  }
  pbVar10 = pbVar7;
  for (psVar8 = (short *)(lVar18 + 0x10); (*psVar8 != 0 && (*psVar8 == *(short *)pbVar10));
      psVar8 = psVar8 + 1) {
    pbVar10 = pbVar10 + 2;
  }
  local_50 = pbVar7;
  if (*psVar8 == *(short *)pbVar10) {
    ppbVar14 = &local_50;
    FUN_000013d0((longlong *)ppbVar14);
    local_54[0] = 1;
  }
  else {
    FUN_0001ae7c(uVar2,0,2,(undefined4 *)local_54,'\0');
    if (local_54[0] == 0) {
      DAT_0018f07c = 0;
      return;
    }
  }
  uVar20 = 0;
  do {
    if (((param_2[5] != 0) && (param_2[6] != 0)) &&
       (pbVar7 = (byte *)FUN_000b1010(ppbVar14,0x40), local_50 = pbVar7, pbVar7 != (byte *)0x0)) {
      pbVar10 = pbVar7;
      lVar17 = DAT_00180188;
      (**(code **)(DAT_00180188 + 0x160))(pbVar7,param_2,0x40);
      lVar16 = param_2[5] - param_2[6];
      puVar9 = FUN_000b1010(pbVar10,lVar16 + 0x100);
      lVar18 = DAT_00180188;
      if (puVar9 == (undefined8 *)0x0) {
        ppbVar14 = &local_50;
        FUN_000013d0((longlong *)ppbVar14);
      }
      else {
        *(undefined8 **)(pbVar7 + 0x30) = puVar9;
        (**(code **)(lVar18 + 0x160))(puVar9,param_2[6],lVar16);
        lVar18 = DAT_00180188;
        pbVar19 = (byte *)((longlong)puVar9 + lVar16);
        *(byte **)(pbVar7 + 0x28) = pbVar19;
        (**(code **)(lVar18 + 0x160))(pbVar19,param_2[5]);
        uVar6 = FUN_00028250((longlong *)pbVar7);
        local_50 = (byte *)CONCAT44(local_50._4_4_,uVar6);
        ppbVar15 = &local_50;
        pbVar10 = FUN_0002847c((longlong)pbVar7,(uint *)ppbVar15,(undefined8 *)0x0);
        iVar1 = (uint)local_50;
        if (pbVar10 != (byte *)0x0) {
          if ((*pbVar19 == 5) && (((uint)local_50 == 0xb || ((uint)local_50 == 0x16)))) {
            if (*pbVar10 == 0x12) {
              *(ushort *)(pbVar10 + 4) = uVar20 - local_58;
            }
            else if (*pbVar10 == 0x14) {
              *(ushort *)(pbVar10 + 6) = uVar20 - local_58;
            }
          }
          else if (*pbVar10 == 0x12) {
            *(ushort *)(pbVar10 + 4) = uVar20;
          }
          else if (*pbVar10 == 0x14) {
            *(ushort *)(pbVar10 + 6) = uVar20;
          }
        }
        if (((uint)local_50 - 0xb < 2) && (*pbVar19 != 5)) {
          ppbVar14 = (byte **)(ulonglong)uVar20;
          bVar3 = FUN_0000de6c(uVar20,ppbVar15,'\0',CONCAT71((int7)((ulonglong)lVar17 >> 8),1));
          if (bVar3) goto LAB_0006c2a9;
        }
        if ((((iVar1 - 0xbU < 2) || (iVar1 == 0x16)) && (1 < (int)param_2[1] - 9U)) &&
           ((1 < (int)param_2[1] - 0x18U && (uVar11 = (ulonglong)uVar20, uVar11 < DAT_00193880)))) {
          ppbVar14 = (byte **)(uVar11 * 9);
          lVar18 = DAT_00193878;
          if (iVar1 == 0x16) {
            lVar18 = DAT_00193868;
          }
          if ((*(byte *)(lVar18 + 4 + uVar11 * 0x48) & 8) != 0) {
            local_58 = local_58 + 1;
            goto LAB_0006c2a9;
          }
        }
        if (*pbVar19 == 5) {
          sVar4 = FUN_00026be4(pbVar19);
          lVar18 = 0xffff;
          if (sVar4 == -1) {
            pbVar10 = (byte *)0x0;
          }
          else {
            lVar18 = *param_2;
            pbVar10 = (byte *)FUN_000484c8(lVar18,sVar4,(short *)0x0);
          }
          lVar17 = 0;
          if (pbVar10 == (byte *)0x0) {
            local_50 = pbVar10;
            pbVar10 = (byte *)FUN_000b1010(lVar18,4);
            if (pbVar10 == (byte *)0x0) {
              return;
            }
            sVar4 = 0x20;
            lVar18 = (longlong)&DAT_0016bdcc - (longlong)pbVar10;
            pbVar12 = pbVar10;
            do {
              *(short *)pbVar12 = sVar4;
              pbVar12 = pbVar12 + 2;
              sVar4 = *(short *)(pbVar12 + lVar18);
            } while (sVar4 != 0);
            pbVar12[0] = 0;
            pbVar12[1] = 0;
          }
          if (*(short *)pbVar10 != 0) {
            lVar18 = 1;
            pbVar12 = pbVar10;
            do {
              pbVar12 = pbVar12 + 2;
              lVar17 = lVar17 + 1;
            } while (*(short *)pbVar12 != 0);
          }
          uVar11 = lVar17 * 2 + 0x14;
          local_50 = pbVar10;
          pcVar13 = (char *)FUN_000b1010(lVar18,uVar11);
          local_48[0] = pcVar13;
          FUN_00009d1c(pcVar13,uVar11,pbVar10,(ulonglong)(((uint)uVar20 - (uint)local_58) + 1));
          uVar5 = FUN_00028634((longlong *)pbVar7,&local_res18);
          sVar4 = FUN_00009e3c(*param_2,(longlong)pcVar13);
          if ((4 < *pbVar19) &&
             (((*pbVar19 < 9 || (*pbVar19 == 0xf)) ||
              (((byte)(*pbVar19 - 0x1a) < 3 || (*pbVar19 == 0x23)))))) {
            *(short *)(pbVar19 + 2) = sVar4;
          }
          if (**(char **)(pbVar7 + 0x28) == '\x05') {
            *(ushort *)(*(char **)(pbVar7 + 0x28) + 10) = uVar5 * 2;
          }
          iVar1 = *(int *)(local_res18 + 100);
          if (iVar1 == 1) {
            if (*(int *)(pbVar7 + 8) == 7) {
              FUN_00017104((longlong *)pbVar7,uVar5);
              goto LAB_0006c59f;
            }
          }
          else if (iVar1 == 5) {
            if (DAT_00193888 != 0) {
              FUN_00016ad4((longlong *)pbVar7);
            }
          }
          else {
            if (iVar1 == 7) {
              FUN_0001742c((longlong *)pbVar7,uVar5);
            }
            else {
              if (((iVar1 == 9) || (iVar1 != 0x12)) || (*(int *)(pbVar7 + 8) != 0x17))
              goto LAB_0006c5ad;
              FUN_00017298((longlong *)pbVar7,uVar5);
            }
LAB_0006c59f:
            if (uVar20 != 0) {
              FUN_00036f08((longlong)pbVar7);
            }
          }
LAB_0006c5ad:
          FUN_000013d0((longlong *)local_48);
          FUN_000013d0((longlong *)&local_50);
        }
        FUN_0006bbc0((undefined8 *)*param_1,(longlong *)pbVar7,local_res20);
        ppbVar14 = (byte **)*param_1;
        if (local_res20 == '\x01') {
          FUN_0006b9c8((longlong)ppbVar14,(longlong)pbVar7);
        }
        else {
          if (ppbVar14 == (byte **)0x0) {
            DAT_0018f07c = 0;
            return;
          }
          *(byte **)(*ppbVar14 + 0x10) = pbVar7;
          *param_1 = (longlong)ppbVar14[9];
        }
      }
    }
LAB_0006c2a9:
    uVar20 = uVar20 + 1;
    if (local_54[0] <= uVar20) {
      DAT_0018f07c = 0;
      return;
    }
  } while( true );
}

