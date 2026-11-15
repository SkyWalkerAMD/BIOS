
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong WS05_1fcb4(longlong param_1,undefined8 param_2,word *param_3)

{
  uint *puVar1;
  short sVar2;
  wchar_t wVar3;
  char cVar4;
  undefined7 extraout_var;
  ulonglong uVar5;
  char *pcVar6;
  short *psVar7;
  undefined8 *puVar8;
  char *pcVar9;
  longlong lVar10;
  undefined8 uVar11;
  uint uVar12;
  uint *puVar13;
  wchar_t *pwVar14;
  undefined4 *puVar15;
  uint *puVar16;
  uint *puVar17;
  code *pcVar18;
  longlong lVar19;
  uint *puVar20;
  byte *pbVar21;
  longlong *plVar22;
  uint *puVar23;
  uint uVar24;
  longlong local_res8;
  longlong local_res10;
  longlong local_res18;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  short local_68;
  short asStack_66 [4];
  undefined2 uStack_5e;
  undefined2 uStack_5c;
  undefined2 uStack_5a;
  undefined2 local_58;
  wchar_t local_50;
  wchar_t awStack_4e [4];
  wchar_t wStack_46;
  wchar_t wStack_44;
  wchar_t wStack_42;
  wchar_t local_40 [2];
  wchar_t local_3c;
  
  puVar23 = (uint *)0x0;
  local_78 = 0xd84beff0;
  local_74 = 0x4b60159a;
  local_70 = 0x5cacb99a;
  local_6c = 0xb1d34b47;
  local_88 = 0x1b6bc809;
  local_84 = 0x4937c986;
  local_80 = 0xa51e4f93;
  local_7c = 0x50fe2286;
  if (param_1 != 0) {
    cVar4 = FUN_0002ae44(param_1,3);
    uVar5 = CONCAT71(extraout_var,cVar4);
    if (cVar4 != '\0') goto LAB_000202f4;
  }
  uVar5 = WS05_497e8();
  if (((char)uVar5 == '\0') &&
     ((DAT_000afdd0 == 0 ||
      (uVar5 = WS05_495f4((ulonglong)
                          *(uint *)(DAT_000baaf0 + 4 + (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 4
                                   ) + DAT_000babc0), (char)uVar5 == '\0')))) {
    puVar13 = (uint *)&DAT_00093458;
    WS05_10704(&DAT_00093458);
    if (DAT_000afdc8 != '\0') {
      local_res8 = CONCAT62(local_res8._2_6_,1);
      uVar24 = *DAT_000baaf8;
      puVar13 = puVar23;
      if (uVar24 != 0) {
        do {
          uVar12 = (uint)puVar13;
          if (((uVar12 < uVar24) &&
              (param_3 = (word *)((ulonglong)DAT_000baaf8[(longlong)((longlong)puVar13 + 1)] +
                                 (longlong)DAT_000baaf8), param_3 != (word *)0x0)) &&
             (*(int *)(param_3 + 0x32) == 0xf017)) {
            param_3 = &IMAGE_DOS_HEADER_00000000.e_cblp;
            FUN_0001ccbc(uVar12,0,2,(ushort *)&local_res8);
            break;
          }
          puVar13 = (uint *)(ulonglong)(uVar12 + 1);
        } while (uVar12 + 1 < uVar24);
      }
    }
    plVar22 = DAT_000afcd8;
    puVar16 = puVar23;
    if (*DAT_000baaf8 != 0) {
      do {
        uVar24 = (uint)puVar16;
        if (uVar24 == 7) {
          local_res10 = 0;
          WS05_1e6f8(puVar13);
          pcVar6 = (char *)FUN_00059b50(puVar13,plVar22[1]);
          (**(code **)(DAT_000afbc8 + 0x160))(pcVar6,*plVar22,plVar22[1]);
          puVar13 = puVar23;
          puVar16 = puVar23;
          puVar17 = DAT_000bab90;
          if (DAT_000bab90 != (uint *)0x0) {
            do {
              uVar12 = *(uint *)((longlong)puVar13 + DAT_000bab88 + 4);
              if ((uVar12 & 8) == 0) {
                *(uint *)((longlong)puVar13 + DAT_000bab88 + 4) = uVar12 & 0xfffffffe;
                puVar17 = DAT_000bab90;
              }
              puVar16 = (uint *)((longlong)puVar16 + 1);
              puVar13 = puVar13 + 0x12;
            } while (puVar16 < puVar17);
          }
          puVar13 = puVar23;
          if (puVar17 != (uint *)0x0) {
            do {
              psVar7 = FUN_00013298(*(short *)(pcVar6 + (longlong)puVar13 * 2));
              if ((psVar7 != (short *)0x0) && ((*(uint *)(psVar7 + 2) & 8) == 0)) {
                *(uint *)(psVar7 + 2) = *(uint *)(psVar7 + 2) | 1;
                puVar17 = DAT_000bab90;
              }
              puVar13 = (uint *)((longlong)puVar13 + 1);
            } while (puVar13 < puVar17);
          }
          puVar13 = puVar23;
          puVar16 = puVar23;
          puVar20 = (uint *)0x0;
          if (puVar17 != (uint *)0x0) {
            do {
              psVar7 = &local_68;
              local_58 = DAT_000a8e40;
              local_68 = _DAT_000a8e30;
              asStack_66[0] = uRam00000000000a8e32;
              asStack_66[1] = uRam00000000000a8e34;
              asStack_66[2] = uRam00000000000a8e36;
              asStack_66[3] = uRam00000000000a8e38;
              uStack_5e = uRam00000000000a8e3a;
              uStack_5c = uRam00000000000a8e3c;
              uStack_5a = uRam00000000000a8e3e;
              local_res8 = 0;
              puVar17 = puVar23;
              sVar2 = _DAT_000a8e30;
              while (sVar2 != 0) {
                psVar7 = psVar7 + 1;
                puVar17 = (uint *)((longlong)puVar17 + 1);
                sVar2 = *psVar7;
              }
              FUN_00017908((char *)&local_68,(longlong)puVar17 * 2 + 2,(byte *)u_Boot_04X_000948c0,
                           (ulonglong)*(ushort *)((longlong)puVar13 + DAT_000bab88));
              puVar8 = FUN_00007758(&local_68,&DAT_000930a0,(undefined4 *)0x0,&local_res8);
              lVar19 = DAT_000afbd8;
              if (puVar8 != (undefined8 *)0x0) {
                *(undefined4 *)puVar8 = *(undefined4 *)((longlong)puVar13 + DAT_000bab88 + 4);
                (**(code **)(lVar19 + 0x58))(&local_68,&DAT_000930a0,7,local_res8,puVar8);
                (**(code **)(DAT_000afbc8 + 0x48))(puVar8);
              }
              puVar16 = (uint *)((longlong)puVar16 + 1);
              puVar13 = puVar13 + 0x12;
              puVar20 = DAT_000bab90;
            } while (puVar16 < DAT_000bab90);
          }
          sVar2 = DAT_000bab50;
          puVar13 = puVar23;
          puVar16 = puVar23;
          if (puVar20 != (uint *)0x0) {
            do {
              if ((sVar2 == *(short *)(pcVar6 + (longlong)puVar13 * 2)) && (puVar16 < puVar20)) {
                pbVar21 = (byte *)(DAT_000bab88 + 4 + (longlong)puVar16 * 0x48);
                puVar17 = puVar16;
                do {
                  puVar1 = (uint *)((longlong)puVar17 + 1);
                  if ((*pbVar21 & 9) == 0) {
                    *(undefined2 *)(pcVar6 + (longlong)puVar13 * 2) =
                         *(undefined2 *)(DAT_000bab88 + (longlong)puVar17 * 0x48);
                    puVar16 = puVar1;
                    puVar20 = DAT_000bab90;
                    break;
                  }
                  pbVar21 = pbVar21 + 0x48;
                  puVar17 = puVar1;
                } while (puVar1 < puVar20);
              }
              puVar13 = (uint *)((longlong)puVar13 + 1);
            } while (puVar13 < puVar20);
          }
          pcVar9 = (char *)FUN_00007758(u_BootOrder_000a8350,&DAT_000930a0,(undefined4 *)0x0,
                                        &local_res10);
          lVar19 = (longlong)puVar13 * 2;
          if (local_res10 == lVar19) {
            if (pcVar9 != (char *)0x0) {
              if (((local_res10 != 0) && (pcVar9 != pcVar6)) &&
                 (lVar10 = FUN_000015e0(pcVar9,pcVar6,local_res10), lVar10 != 0)) {
                WS05_10704(&local_88);
              }
              goto LAB_0002003d;
            }
          }
          else {
            WS05_10704(&local_88);
            if (pcVar9 != (char *)0x0) {
LAB_0002003d:
              (**(code **)(DAT_000afbc8 + 0x48))(pcVar9);
            }
          }
          pwVar14 = u_BootOrder_000a8350;
LAB_00020054:
          param_3 = (word *)((longlong)&IMAGE_DOS_HEADER_00000000.e_crlc + 1);
          (**(code **)(DAT_000afbd8 + 0x58))(pwVar14,&DAT_000930a0,7,lVar19,pcVar6);
          if (pcVar6 != (char *)0x0) {
            (**(code **)(DAT_000afbc8 + 0x48))(pcVar6);
          }
        }
        else {
          if (uVar24 == 0x17) {
            pcVar6 = (char *)FUN_00059b50(puVar13,plVar22[1]);
            (**(code **)(DAT_000afbc8 + 0x160))(pcVar6,*plVar22,plVar22[1]);
            puVar13 = puVar23;
            puVar16 = puVar23;
            puVar17 = _DAT_000bab78;
            if (_DAT_000bab78 != (uint *)0x0) {
              do {
                uVar12 = *(uint *)((longlong)puVar13 + DAT_000bab80 + 4);
                if ((uVar12 & 8) == 0) {
                  *(uint *)((longlong)puVar13 + DAT_000bab80 + 4) = uVar12 & 0xfffffffe;
                  puVar17 = _DAT_000bab78;
                }
                puVar16 = (uint *)((longlong)puVar16 + 1);
                puVar13 = puVar13 + 0x12;
              } while (puVar16 < puVar17);
            }
            puVar13 = puVar23;
            if (puVar17 != (uint *)0x0) {
              do {
                psVar7 = FUN_000132c4(*(short *)(pcVar6 + (longlong)puVar13 * 2));
                if ((psVar7 != (short *)0x0) && ((*(uint *)(psVar7 + 2) & 8) == 0)) {
                  *(uint *)(psVar7 + 2) = *(uint *)(psVar7 + 2) | 1;
                  puVar17 = _DAT_000bab78;
                }
                puVar13 = (uint *)((longlong)puVar13 + 1);
              } while (puVar13 < puVar17);
            }
            puVar13 = puVar23;
            puVar16 = puVar23;
            puVar20 = (uint *)0x0;
            if (puVar17 != (uint *)0x0) {
              do {
                pwVar14 = &local_50;
                local_40[0] = u_DriverXXXX_000a8e48[8];
                local_40[1] = u_DriverXXXX_000a8e48[9];
                local_3c = u_DriverXXXX_000a8e48[10];
                local_50 = u_DriverXXXX_000a8e48[0];
                awStack_4e[0] = u_DriverXXXX_000a8e48[1];
                awStack_4e[1] = u_DriverXXXX_000a8e48[2];
                awStack_4e[2] = u_DriverXXXX_000a8e48[3];
                awStack_4e[3] = u_DriverXXXX_000a8e48[4];
                wStack_46 = u_DriverXXXX_000a8e48[5];
                wStack_44 = u_DriverXXXX_000a8e48[6];
                wStack_42 = u_DriverXXXX_000a8e48[7];
                local_res18 = 0;
                puVar17 = puVar23;
                wVar3 = u_DriverXXXX_000a8e48[0];
                while (wVar3 != L'\0') {
                  pwVar14 = pwVar14 + 1;
                  puVar17 = (uint *)((longlong)puVar17 + 1);
                  wVar3 = *pwVar14;
                }
                FUN_00017908((char *)&local_50,(longlong)puVar17 * 2 + 2,
                             (byte *)u_Driver_04X_000948d8,
                             (ulonglong)*(ushort *)((longlong)puVar13 + DAT_000bab80));
                puVar8 = FUN_00007758(&local_50,&DAT_000930a0,(undefined4 *)0x0,&local_res18);
                lVar19 = DAT_000afbd8;
                if (puVar8 != (undefined8 *)0x0) {
                  *(undefined4 *)puVar8 = *(undefined4 *)((longlong)puVar13 + DAT_000bab80 + 4);
                  (**(code **)(lVar19 + 0x58))(&local_50,&DAT_000930a0,7,local_res18,puVar8);
                  (**(code **)(DAT_000afbc8 + 0x48))(puVar8);
                }
                puVar16 = (uint *)((longlong)puVar16 + 1);
                puVar13 = puVar13 + 0x12;
                puVar20 = _DAT_000bab78;
              } while (puVar16 < _DAT_000bab78);
            }
            sVar2 = DAT_000bab50;
            puVar13 = puVar23;
            puVar16 = puVar23;
            if (puVar20 != (uint *)0x0) {
              do {
                if ((sVar2 == *(short *)(pcVar6 + (longlong)puVar13 * 2)) && (puVar16 < puVar20)) {
                  pbVar21 = (byte *)(DAT_000bab80 + 4 + (longlong)puVar16 * 0x48);
                  puVar17 = puVar16;
                  do {
                    puVar1 = (uint *)((longlong)puVar17 + 1);
                    if ((*pbVar21 & 9) == 0) {
                      *(undefined2 *)(pcVar6 + (longlong)puVar13 * 2) =
                           *(undefined2 *)(DAT_000bab80 + (longlong)puVar17 * 0x48);
                      puVar20 = _DAT_000bab78;
                      puVar16 = puVar1;
                      break;
                    }
                    pbVar21 = pbVar21 + 0x48;
                    puVar17 = puVar1;
                  } while (puVar1 < puVar20);
                }
                puVar13 = (uint *)((longlong)puVar13 + 1);
              } while (puVar13 < puVar20);
            }
            lVar19 = (longlong)puVar13 * 2;
            pwVar14 = u_DriverOrder_000a8660;
            goto LAB_00020054;
          }
          if (uVar24 != 8) {
            param_3 = (word *)plVar22[1];
            WS05_1c958(uVar24,*plVar22,(ulonglong)param_3);
          }
        }
        puVar16 = (uint *)(ulonglong)(uVar24 + 1);
        plVar22 = plVar22 + 2;
        puVar13 = DAT_000baaf8;
      } while (uVar24 + 1 < *DAT_000baaf8);
    }
    pcVar18 = WS05_69ec;
    WS05_fd18(0xffff000d,WS05_69ec);
    puVar15 = &local_78;
    WS05_10704(puVar15);
    DAT_000afe11 = 0;
    uVar11 = WS05_4037c((longlong)puVar15,pcVar18,(undefined8 *)param_3);
    return CONCAT71((int7)((ulonglong)uVar11 >> 8),1);
  }
LAB_000202f4:
  return uVar5 & 0xffffffffffffff00;
}

