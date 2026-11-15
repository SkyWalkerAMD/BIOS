
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulonglong Candidate_ACE_SaveIterator(longlong param_1,undefined8 param_2,word *param_3)

{
  short sVar1;
  wchar_t wVar2;
  uint uVar3;
  wchar_t *pwVar4;
  char cVar5;
  undefined7 extraout_var;
  ulonglong uVar6;
  char *pcVar7;
  short *psVar8;
  undefined8 uVar9;
  uint *puVar10;
  char **ppcVar11;
  undefined4 *puVar12;
  ulonglong uVar13;
  ulonglong uVar14;
  undefined1 *puVar15;
  byte *pbVar16;
  uint uVar17;
  ulonglong uVar18;
  ulonglong uVar19;
  longlong *plVar20;
  char *local_res8;
  char *local_res10;
  longlong local_res18;
  undefined8 *local_res20;
  char *local_a8;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  short local_80;
  short asStack_7e [4];
  undefined2 uStack_76;
  undefined2 uStack_74;
  undefined2 uStack_72;
  undefined2 local_70;
  wchar_t local_68;
  wchar_t awStack_66 [4];
  wchar_t wStack_5e;
  wchar_t wStack_5c;
  wchar_t wStack_5a;
  wchar_t local_58 [2];
  wchar_t local_54;
  
  uVar19 = 0;
  local_90 = 0xd84beff0;
  local_8c = 0x4b60159a;
  local_88 = 0x5cacb99a;
  local_84 = 0xb1d34b47;
  local_a0 = 0x1b6bc809;
  local_9c = 0x4937c986;
  local_98 = 0xa51e4f93;
  local_94 = 0x50fe2286;
  uVar17 = 0;
  if (param_1 != 0) {
    cVar5 = FUN_00019ef4(param_1,3);
    uVar6 = CONCAT71(extraout_var,cVar5);
    if (cVar5 != '\0') goto LAB_00014321;
  }
  uVar6 = FUN_00032484();
  if (((char)uVar6 == '\0') &&
     ((DAT_00082748 == 0 ||
      (uVar6 = FUN_000322b4((ulonglong)
                            *(uint *)(DAT_00092270 + 4 +
                                     (ulonglong)*(uint *)(DAT_00082748 + 0x28) * 4) + DAT_00092b08),
      (char)uVar6 == '\0')))) {
    FUN_000064e4(&DAT_0006a5a0);
    if (DAT_00082740 != '\0') {
      local_res8 = (char *)CONCAT62(local_res8._2_6_,1);
      if (*DAT_00092278 != 0) {
        uVar6 = uVar19;
        if (*DAT_00092278 == 0) goto LAB_0001439b;
        do {
          uVar17 = (uint)uVar6;
          uVar6 = (ulonglong)DAT_00092278[uVar6 + 1] + (longlong)DAT_00092278;
          if ((uVar6 != 0) && (*(int *)(uVar6 + 100) == 0xf017)) goto LAB_000143aa;
LAB_0001439b:
          uVar6 = (ulonglong)(uVar17 + 1);
        } while (uVar17 + 1 < *DAT_00092278);
      }
      uVar6 = uVar19;
      uVar17 = (uint)local_res8;
LAB_000143aa:
      if (uVar6 != 0) {
        param_3 = &IMAGE_DOS_HEADER_00000000.e_cblp;
        FUN_00011518(uVar17,0,2,(ushort *)&local_res8);
      }
    }
    puVar10 = DAT_00092278;
    uVar6 = uVar19;
    plVar20 = DAT_00082650;
    if (*DAT_00092278 != 0) {
      do {
        uVar17 = (uint)uVar6;
        if (uVar17 == 7) {
          local_res10 = (char *)0x0;
          FUN_00012f18(puVar10);
          pcVar7 = (char *)FUN_0003eea8(puVar10,plVar20[1]);
          local_a8 = pcVar7;
          (**(code **)(DAT_000824c8 + 0x160))(pcVar7,*plVar20,plVar20[1]);
          uVar6 = uVar19;
          uVar13 = uVar19;
          uVar14 = DAT_00092ad8;
          if (DAT_00092ad8 != 0) {
            do {
              uVar3 = *(uint *)(uVar6 + 4 + DAT_00092ad0);
              if ((uVar3 & 8) == 0) {
                *(uint *)(uVar6 + 4 + DAT_00092ad0) = uVar3 & 0xfffffffe;
                uVar14 = DAT_00092ad8;
              }
              uVar13 = uVar13 + 1;
              uVar6 = uVar6 + 0x48;
            } while (uVar13 < uVar14);
          }
          uVar6 = uVar19;
          if (uVar14 != 0) {
            do {
              psVar8 = FUN_000090f8(*(short *)(pcVar7 + uVar6 * 2));
              if ((psVar8 != (short *)0x0) && ((*(uint *)(psVar8 + 2) & 8) == 0)) {
                *(uint *)(psVar8 + 2) = *(uint *)(psVar8 + 2) | 1;
                uVar14 = DAT_00092ad8;
              }
              uVar6 = uVar6 + 1;
            } while (uVar6 < uVar14);
          }
          uVar6 = uVar19;
          uVar13 = uVar19;
          uVar18 = 0;
          if (uVar14 != 0) {
            do {
              psVar8 = &local_80;
              local_70 = DAT_0007bd40;
              local_80 = _DAT_0007bd30;
              asStack_7e[0] = uRam000000000007bd32;
              asStack_7e[1] = uRam000000000007bd34;
              asStack_7e[2] = uRam000000000007bd36;
              asStack_7e[3] = uRam000000000007bd38;
              uStack_76 = uRam000000000007bd3a;
              uStack_74 = uRam000000000007bd3c;
              uStack_72 = uRam000000000007bd3e;
              local_res8 = (char *)0x0;
              uVar14 = uVar19;
              sVar1 = _DAT_0007bd30;
              while (sVar1 != 0) {
                psVar8 = psVar8 + 1;
                uVar14 = uVar14 + 1;
                sVar1 = *psVar8;
              }
              FUN_0000cb44((char *)&local_80,uVar14 * 2 + 2,(byte *)u_Boot_04X_0006ba40,
                           (ulonglong)*(ushort *)(uVar6 + DAT_00092ad0));
              local_res20 = FUN_000013e4(&local_80,&DAT_0006a250,(undefined4 *)0x0,
                                         (longlong *)&local_res8);
              if (local_res20 != (undefined8 *)0x0) {
                *(undefined4 *)local_res20 = *(undefined4 *)(uVar6 + 4 + DAT_00092ad0);
                (**(code **)(DAT_000824d8 + 0x58))(&local_80,&DAT_0006a250,7,local_res8,local_res20)
                ;
                FUN_00005958((longlong *)&local_res20);
              }
              uVar13 = uVar13 + 1;
              uVar6 = uVar6 + 0x48;
              uVar18 = DAT_00092ad8;
            } while (uVar13 < DAT_00092ad8);
          }
          sVar1 = DAT_00092a98;
          uVar13 = uVar19;
          uVar6 = uVar19;
          if (uVar18 != 0) {
            do {
              if ((sVar1 == *(short *)(pcVar7 + uVar13 * 2)) && (uVar6 < uVar18)) {
                pbVar16 = (byte *)(DAT_00092ad0 + 4 + uVar6 * 0x48);
                uVar14 = uVar6;
                do {
                  if ((*pbVar16 & 9) == 0) {
                    uVar6 = uVar14 + 1;
                    *(undefined2 *)(pcVar7 + uVar13 * 2) =
                         *(undefined2 *)(DAT_00092ad0 + uVar14 * 0x48);
                    uVar18 = DAT_00092ad8;
                    break;
                  }
                  uVar14 = uVar14 + 1;
                  pbVar16 = pbVar16 + 0x48;
                } while (uVar14 < uVar18);
              }
              uVar13 = uVar13 + 1;
            } while (uVar13 < uVar18);
          }
          local_res8 = (char *)FUN_000013e4(u_BootOrder_0007b170,&DAT_0006a250,(undefined4 *)0x0,
                                            (longlong *)&local_res10);
          if (local_res10 == (char *)(uVar13 * 2)) {
            if (local_res8 != (char *)0x0) {
              uVar6 = uVar19;
              if ((local_res10 != (char *)0x0) && (local_res8 != pcVar7)) {
                uVar6 = FUN_000003a0(local_res8,pcVar7,(longlong)local_res10);
              }
              if (uVar6 != 0) goto LAB_0001461f;
            }
          }
          else {
LAB_0001461f:
            FUN_000064e4(&local_a0);
          }
          FUN_00005958((longlong *)&local_res8);
          param_3 = (word *)((longlong)&IMAGE_DOS_HEADER_00000000.e_crlc + 1);
          (**(code **)(DAT_000824d8 + 0x58))
                    (u_BootOrder_0007b170,&DAT_0006a250,7,(char *)(uVar13 * 2),pcVar7);
          ppcVar11 = &local_a8;
LAB_0001465b:
          FUN_00005958((longlong *)ppcVar11);
          puVar10 = DAT_00092278;
        }
        else {
          if (uVar17 == 0x17) {
            pcVar7 = (char *)FUN_0003eea8(puVar10,plVar20[1]);
            local_res10 = pcVar7;
            (**(code **)(DAT_000824c8 + 0x160))(pcVar7,*plVar20,plVar20[1]);
            uVar6 = uVar19;
            uVar13 = uVar19;
            uVar14 = DAT_00092ac0;
            if (DAT_00092ac0 != 0) {
              do {
                uVar3 = *(uint *)(uVar6 + 4 + DAT_00092ac8);
                if ((uVar3 & 8) == 0) {
                  *(uint *)(uVar6 + 4 + DAT_00092ac8) = uVar3 & 0xfffffffe;
                  uVar14 = DAT_00092ac0;
                }
                uVar13 = uVar13 + 1;
                uVar6 = uVar6 + 0x48;
              } while (uVar13 < uVar14);
            }
            uVar6 = uVar19;
            if (uVar14 != 0) {
              do {
                psVar8 = FUN_00009130(*(short *)(pcVar7 + uVar6 * 2));
                if ((psVar8 != (short *)0x0) && ((*(uint *)(psVar8 + 2) & 8) == 0)) {
                  *(uint *)(psVar8 + 2) = *(uint *)(psVar8 + 2) | 1;
                  uVar14 = DAT_00092ac0;
                }
                uVar6 = uVar6 + 1;
              } while (uVar6 < uVar14);
            }
            uVar6 = uVar19;
            uVar13 = uVar19;
            uVar18 = 0;
            if (uVar14 != 0) {
              do {
                pwVar4 = &local_68;
                local_58[0] = u_DriverXXXX_0007bd48[8];
                local_58[1] = u_DriverXXXX_0007bd48[9];
                local_54 = u_DriverXXXX_0007bd48[10];
                local_68 = u_DriverXXXX_0007bd48[0];
                awStack_66[0] = u_DriverXXXX_0007bd48[1];
                awStack_66[1] = u_DriverXXXX_0007bd48[2];
                awStack_66[2] = u_DriverXXXX_0007bd48[3];
                awStack_66[3] = u_DriverXXXX_0007bd48[4];
                wStack_5e = u_DriverXXXX_0007bd48[5];
                wStack_5c = u_DriverXXXX_0007bd48[6];
                wStack_5a = u_DriverXXXX_0007bd48[7];
                local_res18 = 0;
                uVar14 = uVar19;
                wVar2 = u_DriverXXXX_0007bd48[0];
                while (wVar2 != L'\0') {
                  pwVar4 = pwVar4 + 1;
                  uVar14 = uVar14 + 1;
                  wVar2 = *pwVar4;
                }
                FUN_0000cb44((char *)&local_68,uVar14 * 2 + 2,(byte *)u_Driver_04X_0006ba58,
                             (ulonglong)*(ushort *)(uVar6 + DAT_00092ac8));
                local_res8 = (char *)FUN_000013e4(&local_68,&DAT_0006a250,(undefined4 *)0x0,
                                                  &local_res18);
                if (local_res8 != (char *)0x0) {
                  *(undefined4 *)local_res8 = *(undefined4 *)(uVar6 + 4 + DAT_00092ac8);
                  (**(code **)(DAT_000824d8 + 0x58))
                            (&local_68,&DAT_0006a250,7,local_res18,local_res8);
                  FUN_00005958((longlong *)&local_res8);
                }
                uVar13 = uVar13 + 1;
                uVar6 = uVar6 + 0x48;
                uVar18 = DAT_00092ac0;
              } while (uVar13 < DAT_00092ac0);
            }
            sVar1 = DAT_00092a98;
            uVar6 = uVar19;
            uVar13 = uVar19;
            if (uVar18 != 0) {
              do {
                if ((sVar1 == *(short *)(pcVar7 + uVar13 * 2)) && (uVar6 < uVar18)) {
                  pbVar16 = (byte *)(DAT_00092ac8 + 4 + uVar6 * 0x48);
                  uVar14 = uVar6;
                  do {
                    if ((*pbVar16 & 9) == 0) {
                      uVar6 = uVar14 + 1;
                      *(undefined2 *)(pcVar7 + uVar13 * 2) =
                           *(undefined2 *)(DAT_00092ac8 + uVar14 * 0x48);
                      uVar18 = DAT_00092ac0;
                      break;
                    }
                    uVar14 = uVar14 + 1;
                    pbVar16 = pbVar16 + 0x48;
                  } while (uVar14 < uVar18);
                }
                uVar13 = uVar13 + 1;
              } while (uVar13 < uVar18);
            }
            param_3 = (word *)((longlong)&IMAGE_DOS_HEADER_00000000.e_crlc + 1);
            (**(code **)(DAT_000824d8 + 0x58))
                      (u_DriverOrder_0007b558,&DAT_0006a250,7,uVar13 * 2,pcVar7);
            ppcVar11 = &local_res10;
            goto LAB_0001465b;
          }
          if (uVar17 != 8) {
            param_3 = (word *)plVar20[1];
            Candidate_ACE_VariableCommit(uVar17,*plVar20,(ulonglong)param_3);
            puVar10 = DAT_00092278;
          }
        }
        uVar6 = (ulonglong)(uVar17 + 1);
        plVar20 = plVar20 + 2;
      } while (uVar17 + 1 < *puVar10);
    }
    puVar15 = &LAB_00006370;
    FUN_00005ab8(0xffff000d,&LAB_00006370);
    puVar12 = &local_90;
    FUN_000064e4(puVar12);
    DAT_00082789 = 0;
    uVar9 = FUN_00029d14((longlong)puVar12,puVar15,(undefined8 *)param_3);
    return CONCAT71((int7)((ulonglong)uVar9 >> 8),1);
  }
LAB_00014321:
  return uVar6 & 0xffffffffffffff00;
}

