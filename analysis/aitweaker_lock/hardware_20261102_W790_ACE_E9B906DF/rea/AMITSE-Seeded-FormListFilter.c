
void Candidate_FormListFilter(void)

{
  undefined8 uVar1;
  bool bVar2;
  ushort *puVar3;
  char cVar4;
  short sVar5;
  longlong lVar6;
  char *pcVar7;
  short *psVar8;
  ulonglong uVar9;
  longlong lVar10;
  short *psVar11;
  short *psVar12;
  word *pwVar13;
  longlong lVar14;
  longlong *plVar15;
  word *pwVar16;
  byte bVar17;
  longlong *plVar18;
  ushort **ppuVar19;
  word *pwVar20;
  uint *puVar21;
  longlong *plVar22;
  byte bVar23;
  word *pwVar24;
  longlong *local_res8;
  char local_res10 [8];
  byte local_res18 [8];
  byte local_res20;
  longlong local_9c8;
  undefined4 local_9c0;
  undefined4 local_9bc;
  undefined4 local_9b8;
  undefined4 local_9b4;
  short *local_9b0;
  ushort *local_9a8;
  word *local_9a0;
  word *local_998;
  short local_990 [8];
  ulonglong local_980;
  longlong local_978;
  short *local_970;
  ulonglong local_968;
  uint *local_960;
  undefined8 local_958;
  undefined4 uStack_950;
  undefined4 uStack_94c;
  undefined8 local_948;
  longlong local_940;
  longlong local_938;
  longlong local_928;
  longlong lStack_920;
  longlong local_918;
  short *local_910;
  short *local_908;
  ushort *local_900;
  byte local_8f8;
  uint local_8f4;
  undefined8 local_8f0;
  undefined8 local_8e0;
  undefined8 local_8d8;
  undefined8 uStack_8d0;
  undefined8 local_8c8;
  undefined8 uStack_8c0;
  undefined8 local_8b8;
  longlong local_8a8;
  undefined8 uStack_8a0;
  longlong local_898;
  longlong lStack_890;
  longlong local_888;
  undefined8 uStack_880;
  longlong local_878;
  undefined8 uStack_870;
  longlong local_868;
  undefined8 uStack_860;
  short local_858 [1036];
  
  pwVar16 = (word *)0x0;
  local_9b0 = (short *)0x0;
  local_958._4_4_ = 0;
  uStack_950 = 0;
  uStack_94c = 0;
  local_9a8 = (ushort *)0x0;
  local_998 = (word *)0x0;
  local_9a0 = (word *)0x0;
  local_990[4] = 0x2ea2;
  local_978 = 0;
  local_958._0_4_ = 0;
  local_res18[0] = 0;
  local_res20 = 0;
  local_948 = 1;
  local_9c0 = 0xe770bb69;
  local_9bc = 0x4d04bcb4;
  local_9b8 = 0xff23979e;
  local_9b4 = 0xacfe5694;
  local_990[0] = 0x2712;
  local_990[1] = 0x2714;
  local_990[2] = 0x2716;
  local_990[3] = 0x2719;
  FUN_000616f4(u_<_xml_version__1_0__encoding__UT_000803c0);
  lVar6 = (**(code **)(DAT_000824d8 + 0x48))
                    (u_SystemAccess_0007cb98,&local_9c0,0,&local_948,local_res18);
  if (lVar6 != -0x7ffffffffffffff2) {
    if (lVar6 < 0) goto LAB_000607d7;
    local_res20 = local_res18[0];
  }
  FUN_0004c7e4(2);
LAB_000607d7:
  local_980 = 1;
  pwVar20 = pwVar16;
  if (1 < *DAT_00092270) {
    lVar6 = CONCAT44(local_958._4_4_,(undefined4)local_958);
    uVar1 = CONCAT44(uStack_94c,uStack_950);
    local_9c8 = 0xc;
    pwVar13 = pwVar16;
    pwVar24 = pwVar16;
    do {
      uVar9 = local_980;
      FUN_0006a140((undefined4 *)local_858,0,0x800);
      plVar15 = (longlong *)
                ((ulonglong)*(uint *)(local_9c8 + -4 + (longlong)DAT_00092270) + DAT_00092b08);
      local_958._0_4_ = SUB84(plVar15,0);
      local_958._4_4_ = (undefined4)((ulonglong)plVar15 >> 0x20);
      plVar22 = (longlong *)*plVar15;
      local_958 = plVar15;
      if ((plVar22 == (longlong *)0x0) || ((pwVar13 != (word *)0x0 && (pwVar13 == (word *)plVar22)))
         ) {
LAB_00060892:
        pwVar20 = (word *)0x0;
      }
      else {
        if (((*(uint *)((longlong)plVar15 + 0x14) & 1) != 0) &&
           ((*(byte *)((longlong)plVar15 + 0x14) & 0x20) == 0)) {
          if (uVar9 + 1 < (ulonglong)*DAT_00092270) {
            pwVar24 = (word *)((ulonglong)*(uint *)(local_9c8 + (longlong)DAT_00092270) +
                              DAT_00092b08);
            local_9a0 = pwVar24;
          }
          if ((*DAT_00092270 - 1 == uVar9) || (*(longlong **)pwVar24 != plVar22)) {
            FUN_000616f4(u_<_Pages>_<_Platform>_00080428);
          }
          goto LAB_00060892;
        }
        if (pwVar16 != (word *)plVar22) {
          cVar4 = FUN_000694bc(plVar22,0x7ab10);
          pwVar13 = (word *)0x0;
          if (cVar4 == '\0') {
            pwVar13 = (word *)*plVar15;
            local_998 = pwVar13;
            goto LAB_00060892;
          }
          local_998 = (word *)0x0;
          FUN_00020428((uint)*(ushort *)(plVar15 + 2),&local_940);
          pcVar7 = FUN_00061818((uint *)&local_940);
          FUN_0000cb44((char *)local_858,0x400,(byte *)u_<Platform_Guid___s__Handle__0x_x_00080460,
                       (ulonglong)pcVar7);
          FUN_000616f4(local_858);
          FUN_000616f4(u_<Pages>_000804b0);
          if (pcVar7 != (char *)0x0) {
            (**(code **)(DAT_000824c8 + 0x48))(pcVar7);
          }
        }
        psVar8 = local_990;
        bVar2 = false;
        lVar14 = 5;
        do {
          sVar5 = *psVar8;
          psVar8 = psVar8 + 1;
          if (*(short *)((longlong)plVar15 + 10) == sVar5) {
            bVar2 = true;
          }
          lVar14 = lVar14 + -1;
        } while (lVar14 != 0);
        if (bVar2) goto LAB_00060892;
        ppuVar19 = (ushort **)&DAT_0007b628;
        psVar8 = FUN_00061360((short *)*plVar15,*(undefined2 *)((longlong)plVar15 + 0xe),0x804c8,
                              &DAT_0007b628);
        local_968 = 0;
        local_970 = psVar8;
        if (*(int *)((longlong)plVar15 + 0x1c) != 0) {
          puVar21 = (uint *)(plVar15 + 4);
          do {
            cVar4 = '\0';
            bVar23 = 0;
            local_res8 = (longlong *)((ulonglong)local_res8 & 0xffffffffffffff00);
            local_res10[0] = '\0';
            local_960 = puVar21;
            FUN_00000340(&local_918,0x68);
            plVar22 = (longlong *)((ulonglong)*puVar21 + DAT_00092288);
            if ((plVar22 != (longlong *)0x0) && ((*(uint *)((longlong)plVar22 + 0x1c) & 1) != 0)) {
              bVar17 = bVar23;
              if (*(short *)((longlong)plVar22 + 0x14) == 1) {
                sVar5 = FUN_0001e86c(plVar22,&local_978);
                if (((sVar5 != -2) && ((*(byte *)(local_978 + 0x60) & 1) != 0)) &&
                   (*(int *)(local_978 + 100) == 2)) {
                  if (sVar5 != 3 && sVar5 != 4) goto LAB_00060b84;
                  bVar17 = 1;
                }
              }
              if (((*(ushort *)((longlong)plVar22 + 0x14) < 9) &&
                  ((0x10aU >> (*(ushort *)((longlong)plVar22 + 0x14) & 0x1f) & 1) != 0)) &&
                 ((plVar22[6] != 0 && (bVar17 != 1)))) {
                ppuVar19 = &local_9a8;
                uVar9 = FUN_00060420((longlong)plVar22,*plVar15,&local_9b0,ppuVar19,local_res10,
                                     (byte *)&local_res8);
                if ((char)uVar9 == '\0') goto LAB_00060b84;
                bVar23 = (byte)local_res8;
                cVar4 = local_res10[0];
              }
              if (*(short *)((longlong)plVar22 + 0x14) == 1) {
                if (pwVar20 == (word *)0x0) {
                  ppuVar19 = (ushort **)(ulonglong)*(ushort *)(plVar15 + 2);
                  FUN_0000cb44((char *)local_858,0x400,
                               (byte *)u_<Page_PageID__0x_x__PageParentID_00080330,
                               (ulonglong)ppuVar19);
                  FUN_000616f4(local_858);
                }
                FUN_00020428((uint)*(ushort *)(plVar22 + 3),&local_928);
                if ((local_940 == local_928) && (local_938 == lStack_920)) {
                  plVar18 = &local_8a8;
                  local_8a8 = lVar6;
                  uStack_8a0 = uVar1;
                }
                else {
                  plVar18 = &local_898;
                  local_898 = local_928;
                  lStack_890 = lStack_920;
                }
                ppuVar19 = (ushort **)CONCAT71((int7)((ulonglong)ppuVar19 >> 8),cVar4);
                FUN_00061ab8(plVar22,0,plVar18,(wchar_t *)ppuVar19,bVar23);
                pwVar20 = (word *)((longlong)pwVar20 + 1);
              }
              else if (*(short *)((longlong)plVar22 + 0x14) == 3) {
                if (pwVar20 == (word *)0x0) {
                  ppuVar19 = (ushort **)(ulonglong)*(ushort *)(plVar15 + 2);
                  FUN_0000cb44((char *)local_858,0x400,
                               (byte *)u_<Page_PageID__0x_x__PageParentID_00080330,
                               (ulonglong)ppuVar19);
                  FUN_000616f4(local_858);
                  pwVar20 = (word *)(IMAGE_DOS_HEADER_00000000.e_magic + 1);
                }
                plVar18 = &local_888;
                local_888 = lVar6;
                uStack_880 = uVar1;
LAB_00060c81:
                ppuVar19 = (ushort **)CONCAT71((int7)((ulonglong)ppuVar19 >> 8),cVar4);
                FUN_00061ab8(plVar22,(longlong)&local_918,plVar18,(wchar_t *)ppuVar19,bVar23);
              }
              else if (*(short *)((longlong)plVar22 + 0x14) == 8) {
                if (*(short *)((longlong)plVar15 + 10) != 0x271a) {
                  if (pwVar20 == (word *)0x0) {
                    ppuVar19 = (ushort **)(ulonglong)*(ushort *)(plVar15 + 2);
                    FUN_0000cb44((char *)local_858,0x400,
                                 (byte *)u_<Page_PageID__0x_x__PageParentID_00080330,
                                 (ulonglong)ppuVar19);
                    FUN_000616f4(local_858);
                    pwVar20 = (word *)(IMAGE_DOS_HEADER_00000000.e_magic + 1);
                  }
                  plVar18 = &local_878;
                  local_878 = lVar6;
                  uStack_870 = uVar1;
                  goto LAB_00060c81;
                }
              }
              else {
                ppuVar19 = &local_9a8;
                uVar9 = FUN_00060420((longlong)plVar22,*plVar15,&local_9b0,ppuVar19,local_res10,
                                     (byte *)&local_res8);
                puVar3 = local_9a8;
                lVar14 = 0;
                if ((char)uVar9 != '\0') {
                  lVar10 = FUN_0006123c(local_9a8);
                  psVar12 = local_9b0;
                  if ((char)lVar10 != '\0') {
                    local_900 = puVar3;
                    local_910 = (short *)0x0;
                    local_908 = (short *)0x0;
                    local_8f0 = 0;
                    local_8e0 = 0;
                    local_8d8 = 0;
                    uStack_8d0 = 0;
                    local_8c8 = 0;
                    uStack_8c0 = 0;
                    local_8b8 = 0;
                    local_918 = 0;
                    if (local_9b0 != (short *)0x0) {
                      psVar11 = FUN_00045760(local_9b0);
                      (**(code **)(DAT_000824c8 + 0x48))(psVar12);
                      sVar5 = *psVar11;
                      psVar12 = psVar11;
                      lVar10 = lVar14;
                      while (local_910 = psVar11, sVar5 != 0) {
                        if ((*psVar12 == 0xd) || (*psVar12 == 10)) {
                          *psVar12 = 0x20;
                        }
                        lVar10 = lVar10 + 1;
                        psVar12 = psVar11 + lVar10;
                        psVar8 = local_970;
                        sVar5 = *psVar12;
                      }
                    }
                    psVar12 = FUN_000696b8(*plVar15,(short)plVar22[4]);
                    if (psVar12 != (short *)0x0) {
                      psVar11 = FUN_00045760(psVar12);
                      (**(code **)(DAT_000824c8 + 0x48))(psVar12);
                      sVar5 = *psVar11;
                      psVar12 = psVar11;
                      while (local_908 = psVar11, sVar5 != 0) {
                        if ((*psVar12 == 0xd) || (*psVar12 == 10)) {
                          *psVar12 = 0x20;
                        }
                        lVar14 = lVar14 + 1;
                        psVar12 = psVar11 + lVar14;
                        plVar15 = local_958;
                        psVar8 = local_970;
                        sVar5 = *psVar12;
                      }
                    }
                    local_8f8 = (byte)(*(uint *)((longlong)plVar22 + 0x1c) >> 4) & 1;
                    local_8f4 = (uint)*(ushort *)((longlong)plVar22 + 0x14);
                    local_8e0 = 0;
                    local_918 = 0;
                    FUN_00060268((longlong)&local_918,(longlong)plVar22);
                    if (pwVar20 == (word *)0x0) {
                      ppuVar19 = (ushort **)(ulonglong)*(ushort *)(plVar15 + 2);
                      FUN_0000cb44((char *)local_858,0x400,
                                   (byte *)u_<Page_PageID__0x_x__PageParentID_00080330,
                                   (ulonglong)ppuVar19);
                      FUN_000616f4(local_858);
                      pwVar20 = (word *)(IMAGE_DOS_HEADER_00000000.e_magic + 1);
                    }
                    ppuVar19 = (ushort **)CONCAT71((int7)((ulonglong)ppuVar19 >> 8),local_res10[0]);
                    local_868 = lVar6;
                    uStack_860 = uVar1;
                    FUN_00061ab8(plVar22,(longlong)&local_918,&local_868,(wchar_t *)ppuVar19,
                                 (byte)local_res8);
                    FUN_00060fc0(&local_918);
                    local_9b0 = (short *)0x0;
                    local_9a8 = (ushort *)0x0;
                  }
                }
              }
            }
LAB_00060b84:
            local_968 = local_968 + 1;
            puVar21 = local_960 + 1;
          } while (local_968 < *(uint *)((longlong)plVar15 + 0x1c));
          uVar9 = local_980;
          pwVar24 = local_9a0;
          local_960 = puVar21;
          if (pwVar20 != (word *)0x0) {
            FUN_000616f4(u_<_Page>_000804e0);
            uVar9 = local_980;
            pwVar24 = local_9a0;
          }
        }
        if ((*(short *)((longlong)plVar15 + 0x12) == 0) && (pwVar20 == (word *)0x0)) {
          FUN_0000cb44((char *)local_858,0x400,(byte *)u_<Page_PageID__0x_x__PageParentID_00080330,
                       (ulonglong)*(ushort *)(plVar15 + 2));
          FUN_000616f4(local_858);
          FUN_000616f4(u_<_Page>_000804e0);
        }
        else {
          pwVar20 = (word *)0x0;
        }
        if (uVar9 + 1 < (ulonglong)*DAT_00092270) {
          pwVar24 = (word *)((ulonglong)*(uint *)(local_9c8 + (longlong)DAT_00092270) + DAT_00092b08
                            );
          local_9a0 = pwVar24;
        }
        if ((*DAT_00092270 - 1 == uVar9) || (*(longlong *)pwVar24 != *plVar15)) {
          FUN_000616f4(u_<_Pages>_<_Platform>_00080428);
        }
        pwVar16 = (word *)*plVar15;
        pwVar13 = local_998;
        if (psVar8 != (short *)0x0) {
          (**(code **)(DAT_000824c8 + 0x48))(psVar8);
          pwVar13 = local_998;
        }
      }
      local_980 = uVar9 + 1;
      local_9c8 = local_9c8 + 4;
    } while (local_980 < *DAT_00092270);
  }
  FUN_000616f4(u_<_SetupData>_000804f8);
  plVar22 = (longlong *)DAT_0008b530;
  while (plVar22 != (longlong *)0x0) {
    local_res8 = plVar22;
    if ((word *)*plVar22 != pwVar20) {
      FUN_00005958(plVar22);
    }
    plVar22 = (longlong *)plVar22[2];
    FUN_00005958((longlong *)&local_res8);
  }
  DAT_0008b530 = pwVar20;
  FUN_0004c7e4((uint)local_res20);
  return;
}

