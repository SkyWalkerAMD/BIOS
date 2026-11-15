
word ******* Candidate_ACE_BootManager(undefined8 param_1,undefined *param_2)

{
  longlong *plVar1;
  longlong *plVar2;
  ushort uVar3;
  longlong lVar4;
  ushort uVar5;
  ulonglong uVar6;
  undefined8 *puVar7;
  short *psVar8;
  short *extraout_RAX;
  undefined8 *puVar9;
  undefined8 uVar10;
  wchar_t *pwVar11;
  undefined8 **ppuVar12;
  undefined1 *puVar13;
  code *pcVar14;
  word *******pppppppwVar15;
  ushort uVar16;
  word *******pppppppwVar17;
  char cVar18;
  char cVar19;
  int iVar20;
  char local_res8 [8];
  char local_res10;
  short local_res18 [4];
  undefined4 local_res20;
  ulonglong local_d8;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  longlong local_a0;
  longlong local_98;
  short *local_90;
  ushort *local_88;
  int *local_80;
  undefined8 *local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  
  pppppppwVar17 = (word *******)0x8000000000000003;
  local_98 = 0;
  pppppppwVar15 = (word *******)0x8000000000000003;
  local_res8[0] = '\0';
  local_d8 = 0;
  cVar19 = '\0';
  local_b0 = 0xc48d651c;
  DAT_00082678 = DAT_00082678 + 1;
  local_ac = 0x4ce79d0e;
  local_a8 = 0xd1ed39ad;
  local_a4 = 0x306b83ab;
  local_d0 = 0x1cbfc9b6;
  local_cc = 0x4e9e7f1e;
  local_c8 = 0xcefb1f80;
  local_c4 = 0x6da7924d;
  local_c0 = 0xcad40d6e;
  local_bc = 0x4398c871;
  local_b8 = 0x742d0d91;
  local_b4 = 0x1a7194ee;
  local_res10 = '\0';
  local_88 = (ushort *)0x0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  iVar20 = 0;
  local_res20 = 0;
  local_58 = 8;
  local_a0 = 0;
  if (DAT_00082678 != 1) goto LAB_00002be1;
  puVar13 = &LAB_00006370;
  uVar10 = 0xffff0006;
  FUN_00005ab8(0xffff0006,&LAB_00006370);
  if (DAT_00082638 == 0) {
    FUN_00007a78(uVar10,puVar13);
    DAT_00082670 = 1;
    FUN_00007dd4(uVar10);
  }
  if (DAT_00082650 == 0) {
    FUN_00010a94(uVar10,0);
  }
  FUN_0000d984(&DAT_00082688);
  (**(code **)(DAT_000824c8 + 0x18))(0x1f);
  (**(code **)(DAT_000824c8 + 0x20))(4);
  FUN_00008564();
  FUN_000092c0();
  FUN_00033874();
  DAT_00082628 = 3;
  uVar5 = FUN_0003598c();
  if (uVar5 == 0) {
    local_res8[0] = '\x01';
  }
  param_2 = &LAB_000368a4;
  pwVar11 = (wchar_t *)0xffff0008;
  FUN_00005b0c(0xffff0008,&LAB_000368a4,0,0);
  if ((DAT_0008261c == 0) && (DAT_00082659 != '\x01')) {
LAB_000029aa:
    pppppppwVar15 = (word *******)FUN_00037130();
    if (pppppppwVar15 == (word *******)0x8000000000000003) {
      uVar5 = 0xffff;
      DAT_00082622 = '\x01';
    }
    if (pppppppwVar15 == (word *******)0x8000000000000013) {
      local_res8[0] = '\x01';
    }
    if (DAT_0008261c == 7) {
      uVar6 = FUN_000354ac(pwVar11);
      if (((DAT_00082640 == 0) && ((int)uVar6 != 0)) && ((uVar6 & 1) != 0)) goto LAB_00002968;
    }
    else {
      DAT_0008261c = 0;
    }
    if (uVar5 != 0xffff) {
      param_2 = &LAB_0000272c;
      FUN_0000d90c(&local_98,0x272c,local_res8,2,(ulonglong)uVar5 * 1000000,8);
    }
    FUN_000064e4(&local_d0);
    while (local_res8[0] == '\0') {
      FUN_00034b7c();
      if ((DAT_00082659 == '\0') && (DAT_0008261c == 0)) {
        FUN_00005b0c(0xffff0008,&LAB_000368a4,0,0);
        param_2 = &LAB_00006370;
        FUN_00005ab8(0xffff000f,&LAB_00006370);
      }
      else {
        local_res8[0] = '\x01';
      }
    }
    FUN_000064e4(&local_c0);
    FUN_0000d984(&local_98);
    if ((DAT_00082622 == '\0') && (DAT_0008261c != 0)) {
      param_2 = &DAT_0006c050;
      (**(code **)(DAT_000824d8 + 0x58))(u_BootFlow_0007b158,&DAT_0006c050,2,4,&DAT_0008261c);
      FUN_00037130();
    }
LAB_00002b0d:
    cVar18 = '\0';
    if (DAT_00082640 == 1) {
      DAT_00082659 = cVar18;
    }
    if (DAT_00082659 != '\0') {
      DAT_0006abf8 = 0;
      DAT_00082690 = 1;
      if (DAT_00082628 != 6) {
        DAT_00082628 = 4;
      }
      (*(code *)**(undefined8 **)(DAT_000824c0 + 0x30))(*(undefined8 **)(DAT_000824c0 + 0x30));
      FUN_000040bc();
      pppppppwVar15 = (word *******)FUN_0000e208();
      DAT_00082690 = 0;
      DAT_0006abe8 = DAT_00092b18;
      DAT_0006abf0 = DAT_00092b10;
      DAT_0006abf8 = 1;
      FUN_00007710();
      FUN_00006c38(7);
      param_2 = (code *)0x0;
      FUN_00004690(0,0,DAT_00092b18 - 1,DAT_00092b10);
      DAT_0006ac50 = 0xffff;
      DAT_0006ac48 = 0xffff;
    }
    if (DAT_00082678 == 1) {
      if (DAT_00082622 == '\0') {
        local_d8 = 0;
        ppuVar12 = (undefined8 **)((longlong)&IMAGE_DOS_HEADER_00000000.e_cp + 1);
        FUN_00011e5c(5);
        if (local_d8 < 0x51) {
          pppppppwVar15 = (word *******)FUN_0000df40(ppuVar12,(ulonglong)param_2);
          FUN_0000122c(pppppppwVar15);
        }
        DAT_00082628 = 7;
        if (DAT_0008270a != '\0') {
          FUN_0000cdb8();
        }
        FUN_00005ab8(0xffff0004,&LAB_00036520);
        local_d8 = 0;
        puVar7 = FUN_000013e4(u_BootOrder_0007b170,&DAT_0006a250,(undefined4 *)0x0,
                              (longlong *)&local_d8);
        uVar6 = local_d8 >> 1;
        uVar5 = 0;
        if ((short)uVar6 != 0) {
          do {
            psVar8 = FUN_000090f8(*(short *)((longlong)puVar7 + (ulonglong)uVar5 * 2));
            if ((psVar8 != (short *)0x0) && ((*(byte *)(psVar8 + 2) & 1) == 0)) break;
            uVar5 = uVar5 + 1;
          } while (uVar5 < (ushort)uVar6);
        }
        local_d8 = 0;
        uVar10 = 0;
        param_2 = &DAT_0006a250;
        local_88 = (ushort *)
                   FUN_000013e4(u_BootNext_0007b188,&DAT_0006a250,(undefined4 *)0x0,
                                (longlong *)&local_d8);
        if (local_88 != (ushort *)0x0) {
          if (local_d8 == 2) {
            uVar16 = *local_88;
            param_2 = &DAT_0006a250;
            uVar10 = 7;
            (**(code **)(DAT_000824d8 + 0x58))(u_BootNext_0007b188);
            pppppppwVar17 = pppppppwVar15;
            if (DAT_0008261c == 7) goto LAB_00002968;
            uVar6 = (ulonglong)uVar16;
            psVar8 = FUN_000090f8(uVar16);
            if (psVar8 == (short *)0x0) {
              local_90 = psVar8;
              pppppppwVar15 = (word *******)FUN_0000c524(uVar6);
              cVar18 = '\x01';
              psVar8 = extraout_RAX;
              cVar19 = local_res10;
              local_90 = extraout_RAX;
              if (extraout_RAX == (short *)0x0) goto LAB_00002deb;
            }
            local_res18[0] = *psVar8;
            local_90 = psVar8;
            (**(code **)(DAT_000824d8 + 0x58))(u_BootCurrent_0007b4c0,&DAT_0006a250,6,2,local_res18)
            ;
            plVar1 = (longlong *)(psVar8 + 0xc);
            plVar2 = (longlong *)(psVar8 + 8);
            FUN_00009fc8((word *******)*plVar2,*plVar1,*(undefined8 *)(psVar8 + 0x10),'\x01');
            param_2 = &DAT_0006a250;
            uVar10 = 6;
            (**(code **)(DAT_000824d8 + 0x58))(u_BootCurrent_0007b4c0);
            cVar19 = local_res10;
            if (cVar18 != '\0') {
              if (*plVar2 != 0) {
                FUN_00005958(plVar2);
              }
              if (*(longlong *)(psVar8 + 4) != 0) {
                FUN_00005958((longlong *)(psVar8 + 4));
              }
              if (*plVar1 != 0) {
                FUN_00005958(plVar1);
              }
              FUN_00005958((longlong *)&local_90);
              cVar19 = local_res10;
            }
          }
LAB_00002deb:
          FUN_00005958((longlong *)&local_88);
        }
        if (uVar5 == 0) {
          DAT_00082628 = 9;
          pppppppwVar15 = (word *******)FUN_00037250();
          while (pppppppwVar15 == (word *******)0x8000000000000013) {
            puVar9 = FUN_00033df4(DAT_00092b30,0x11,(short *)0x0);
            local_78 = puVar9;
            if ((puVar9 != (undefined8 *)0x0) &&
               (lVar4 = *(longlong *)(DAT_000824c0 + 0x40), lVar4 != 0)) {
              if (DAT_000826d0 == '\0') {
                if (local_a0 == 0) {
                  pppppppwVar15 =
                       (word *******)(**(code **)(DAT_000824c8 + 0x140))(&DAT_0006a780,0,&local_a0);
                  if (pppppppwVar15 != (word *******)0x0) {
                    local_a0 = 0;
                  }
                  if (local_a0 == 0) goto LAB_00002e96;
                }
                (**(code **)(local_a0 + 8))(puVar9);
              }
              else {
                (**(code **)(lVar4 + 8))(lVar4,puVar9);
              }
LAB_00002e96:
              FUN_00005958((longlong *)&local_78);
            }
            (**(code **)(DAT_000824c8 + 0x60))(1,*(longlong *)(DAT_000824c0 + 0x30) + 0x10);
            param_2 = &LAB_000368a4;
            uVar10 = 0;
            FUN_00005b0c(0xffff0008,&LAB_000368a4,0,0);
            if (DAT_00082659 == '\x01') goto LAB_00002b0d;
            pppppppwVar15 = (word *******)FUN_00037250();
            DAT_0008261c = 0;
          }
        }
        if (DAT_00082659 == '\0') {
          FUN_000040bc();
        }
        for (uVar16 = 0; (DAT_0006abe0 != '\0' && (uVar16 < uVar5)); uVar16 = uVar16 + 1) {
          uVar3 = *(ushort *)((longlong)puVar7 + (ulonglong)uVar16 * 2);
          uVar6 = (ulonglong)uVar3;
          psVar8 = FUN_000090f8(uVar3);
          if ((psVar8 == (short *)0x0) || ((*(byte *)(psVar8 + 2) & 1) == 0)) {
            if ((uint)uVar5 <= uVar16 + 1) goto LAB_00002f83;
          }
          else {
            pppppppwVar15 = FUN_00008fd0(uVar6,(short *)param_2,uVar10);
            if (cVar19 == '\0') {
              FUN_000064e4(&local_b0);
              pppppppwVar17 = pppppppwVar15;
              if (DAT_0008261c == 7) goto LAB_00002968;
              cVar19 = '\x01';
              local_res10 = '\x01';
            }
LAB_00002f83:
            if ((uint)uVar5 <= uVar16 + 1) {
              DAT_00082628 = 10;
              pppppppwVar15 = (word *******)FUN_00037250();
              if (pppppppwVar15 == (word *******)0x8000000000000013) {
                param_2 = &LAB_000368a4;
                uVar10 = 0;
                FUN_00005b0c(0xffff0008,&LAB_000368a4,0,0);
                if (DAT_00082659 == '\x01') goto LAB_00002b0d;
                uVar16 = 0xffff;
              }
            }
          }
        }
        pcVar14 = FUN_0001200c;
        FUN_00006234(0xffff0028,FUN_0001200c);
        param_2 = pcVar14;
        DAT_00082659 = '\x01';
      }
      else {
LAB_00002be1:
        DAT_00082659 = '\x01';
      }
      goto LAB_00002b0d;
    }
    DAT_00082678 = DAT_00082678 + -1;
  }
  else {
    local_d8 = 0;
    param_2 = &DAT_0006c050;
    local_80 = (int *)FUN_000013e4(u_BootFlow_0007b158,&DAT_0006c050,(undefined4 *)0x0,
                                   (longlong *)&local_d8);
    if ((local_80 != (int *)0x0) && (local_d8 == 4)) {
      iVar20 = *local_80;
    }
    pwVar11 = (wchar_t *)&local_80;
    FUN_00005958((longlong *)pwVar11);
    if (iVar20 != 7) {
      if (iVar20 != 0) goto LAB_000029a3;
      param_2 = &DAT_0006c050;
      pwVar11 = u_BootFlow_0007b158;
      (**(code **)(DAT_000824d8 + 0x58))();
      goto LAB_000029aa;
    }
    if ((DAT_0008261c == 7) && (DAT_00082659 != '\x01')) {
LAB_000029a3:
      DAT_0008261c = 0;
      goto LAB_000029aa;
    }
LAB_00002968:
    pppppppwVar15 = pppppppwVar17;
    FUN_00002738();
  }
  return pppppppwVar15;
}

