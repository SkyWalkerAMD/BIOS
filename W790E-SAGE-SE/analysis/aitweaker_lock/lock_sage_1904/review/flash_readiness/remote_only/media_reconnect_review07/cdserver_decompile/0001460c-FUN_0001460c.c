
/* WARNING: Type propagation algorithm not settling */

undefined4 FUN_0001460c(void)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  socklen_t sVar10;
  char *pcVar11;
  size_t sVar12;
  undefined4 uVar13;
  void *pvVar14;
  int *piVar15;
  uint uVar16;
  int iVar17;
  uint uVar18;
  uint uVar19;
  uint *puVar20;
  int iVar21;
  socklen_t *psVar22;
  int iVar23;
  socklen_t *unaff_r6;
  uint uVar24;
  uint uVar25;
  int iVar26;
  bool bVar27;
  bool bVar28;
  socklen_t *psVar29;
  socklen_t sVar30;
  uint local_3f8;
  uint local_3ec;
  int local_3d8;
  socklen_t *local_3d4;
  byte local_3d0;
  char local_3cf;
  ushort local_3ce;
  socklen_t local_3cc;
  socklen_t local_3c8;
  undefined4 local_3c4;
  undefined4 local_3c0;
  uint local_3bc;
  undefined4 local_3b8;
  undefined4 local_3b4;
  undefined4 local_3b0;
  undefined4 local_3ac;
  undefined4 local_3a8;
  undefined1 auStack_3a4 [44];
  sysinfo local_378;
  undefined4 local_338;
  undefined4 uStack_334;
  undefined4 uStack_330;
  undefined4 uStack_32c;
  undefined4 local_328;
  undefined4 uStack_324;
  undefined4 uStack_320;
  undefined4 uStack_31c;
  undefined4 local_318;
  undefined4 uStack_314;
  undefined4 uStack_310;
  undefined4 uStack_30c;
  undefined4 local_308;
  undefined4 uStack_304;
  undefined4 uStack_300;
  undefined4 uStack_2fc;
  char acStack_2f8 [64];
  byte local_2b8 [60];
  uint uStack_27c;
  uint local_278 [32];
  undefined1 auStack_1f8 [132];
  undefined1 local_174 [4];
  socklen_t *local_170;
  int local_16c;
  char acStack_168 [256];
  char acStack_68 [64];
  socklen_t sStack_28;
  
  local_3b4 = 0;
  local_3b0 = 0;
  local_3ac = 0;
  local_3a8 = 0;
  iVar6 = GetVMediaCfg(auStack_3a4,*(undefined4 *)(DAT_000155d4 + 0x68),
                       *(undefined4 *)(DAT_000155d4 + 0x74),*(undefined4 *)(DAT_000155d4 + 0x180));
  iVar4 = DAT_00015508;
  if (iVar6 != 0) {
    IDBG_LINUXAPP_DbgOut(0x80,DAT_00015610,DAT_000156d4,DAT_0001560c);
    return 1;
  }
  uVar7 = 0;
  if (0 < *(int *)(DAT_00015508 + 0x10)) {
    do {
      uVar7 = uVar7 + 1 & 0xff;
    } while ((int)uVar7 < *(int *)(DAT_00015508 + 0x10));
  }
  if (*(int *)(DAT_000155d4 + 0x1e8) == 1) {
    iVar6 = mkfifo(DAT_00015648,DAT_00015640);
    if (iVar6 == -1) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00015684,DAT_000156d4,DAT_00015680);
    }
    local_3f8 = sigwrap_open(DAT_00015648,DAT_00015644);
    if (local_3f8 == 0xffffffff) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_00015650,DAT_000156d4,DAT_0001564c);
      return 1;
    }
  }
  else {
    local_3f8 = 0xffffffff;
  }
  if (*(int *)(DAT_000155d4 + 0x1e4) == 1) {
    iVar6 = mkfifo(DAT_00015600,DAT_00015640);
    if (iVar6 == -1) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00015684,DAT_000156d4,DAT_00015674);
    }
    local_3ec = sigwrap_open(DAT_00015600,DAT_00015644);
    if (local_3ec == 0xffffffff) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_00015608,DAT_000156d4,DAT_00015604);
      if (local_3f8 == 0xffffffff) {
        return 1;
      }
      sigwrap_close(local_3f8);
      return 1;
    }
  }
  else {
    local_3ec = 0xffffffff;
  }
  iVar8 = pipe((int *)DAT_0001567c);
  iVar6 = DAT_0001550c;
  bVar27 = local_3f8 != 0xffffffff;
  bVar28 = local_3ec != 0xffffffff;
  if (iVar8 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001563c,DAT_000156d4,DAT_00015638);
    if (*(int *)(DAT_0001569c + 0x1e8) == 1 && bVar27) {
      sigwrap_close(local_3f8);
    }
    if (*(int *)(DAT_0001569c + 0x1e4) != 1 || !bVar28) {
      return 1;
    }
    sigwrap_close(local_3ec);
    return 1;
  }
  if ((*(uint *)(DAT_0001550c + 0x30) & *(uint *)(DAT_0001550c + 0x34)) == 0xffffffff) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00015698,DAT_000156d4,0x4ff);
    if (*(int *)(DAT_0001569c + 0x1e8) == 1 && bVar27) {
      sigwrap_close(local_3f8);
    }
    if (*(int *)(DAT_0001569c + 0x1e4) == 1 && bVar28) {
      sigwrap_close(local_3ec);
    }
    puVar5 = DAT_000156a0;
    sigwrap_close(*DAT_000156a0);
    sigwrap_close(puVar5[1]);
    return 1;
  }
  uVar7 = local_3f8 + 0x1f;
  if (-1 < (int)local_3f8) {
    uVar7 = local_3f8;
  }
  uVar16 = local_3f8 & 0x1f;
  if (-1 < (int)-local_3f8) {
    uVar16 = -(-local_3f8 & 0x1f);
  }
  uVar18 = local_3ec + 0x1f;
  if (-1 < (int)local_3ec) {
    uVar18 = local_3ec;
  }
  iVar8 = (int)uVar18 >> 5;
  uVar18 = local_3ec & 0x1f;
  if (-1 < (int)-local_3ec) {
    uVar18 = -(-local_3ec & 0x1f);
  }
  uVar16 = 1 << (uVar16 & 0xff);
  iVar1 = (int)uVar7 >> 5;
  uVar7 = 1 << (uVar18 & 0xff);
  local_3d8 = 0;
  local_3d4 = (socklen_t *)0x0;
LAB_0001476c:
  do {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00015514,DAT_000156d4,DAT_00015510);
    puVar20 = &uStack_27c;
    do {
      puVar20 = puVar20 + 1;
      *puVar20 = 0;
    } while (puVar20 != local_278 + 0x1f);
    uVar18 = *(uint *)(iVar6 + 0x30);
    if (uVar18 != 0xffffffff) {
      uVar19 = uVar18 + 0x1f;
      if (-1 < (int)uVar18) {
        uVar19 = uVar18;
      }
      uVar9 = uVar18 & 0x1f;
      if (-1 < (int)-uVar18) {
        uVar9 = -(-uVar18 & 0x1f);
      }
      local_278[(int)uVar19 >> 5] = local_278[(int)uVar19 >> 5] | 1 << (uVar9 & 0xff);
    }
    uVar19 = *(uint *)(iVar6 + 0x34);
    if (uVar19 != 0xffffffff) {
      uVar9 = uVar19 + 0x1f;
      if (-1 < (int)uVar19) {
        uVar9 = uVar19;
      }
      uVar24 = uVar19 & 0x1f;
      if (-1 < (int)-uVar19) {
        uVar24 = -(-uVar19 & 0x1f);
      }
      local_278[(int)uVar9 >> 5] = local_278[(int)uVar9 >> 5] | 1 << (uVar24 & 0xff);
    }
    uVar9 = *DAT_0001567c;
    iVar21 = *(int *)(DAT_000155d4 + 0x1e8);
    uVar24 = uVar9 + 0x1f;
    if (-1 < (int)uVar9) {
      uVar24 = uVar9;
    }
    uVar25 = uVar9 & 0x1f;
    if (-1 < (int)-uVar9) {
      uVar25 = -(-uVar9 & 0x1f);
    }
    local_278[(int)uVar24 >> 5] = local_278[(int)uVar24 >> 5] | 1 << (uVar25 & 0xff);
    if (iVar21 == 1 && bVar27) {
      uVar24 = local_3f8 | (int)local_3f8 >> 0x1f;
      local_278[iVar1] = local_278[iVar1] | uVar16;
    }
    else {
      uVar24 = 0xffffffff;
    }
    iVar21 = *(int *)(iVar4 + 0x10);
    if (*(int *)(DAT_000155d4 + 0x1e4) == 1) {
      if (local_3ec != 0xffffffff) {
        if ((int)uVar24 < (int)local_3ec) {
          uVar24 = local_3ec;
        }
        local_278[iVar8] = local_278[iVar8] | uVar7;
      }
      if (0 < iVar21) {
        iVar26 = 0;
        uVar25 = 0;
        do {
          sVar10 = *(socklen_t *)(iVar4 + uVar25 * 4 + 0x60);
          if (sVar10 != 0) {
            unaff_r6 = &sStack_28 + iVar26;
          }
          uVar25 = uVar25 + 1 & 0xff;
          if (sVar10 != 0) {
            unaff_r6[-0xe3] = sVar10;
            iVar26 = iVar26 + 1;
          }
        } while ((int)uVar25 < iVar21);
        if (iVar26 != 0) {
          clear_invalid_register_session_vmedia(7,&local_3b4,iVar26);
          clear_invalid_register_session_vmedia(10,&local_3b4,iVar26);
          uVar18 = *(uint *)(iVar6 + 0x30);
          uVar9 = *DAT_0001567c;
          uVar19 = *(uint *)(iVar6 + 0x34);
          iVar21 = *(int *)(iVar4 + 0x10);
        }
      }
    }
    if ((int)uVar9 <= (int)uVar24) {
      uVar9 = uVar24;
    }
    if ((uVar18 != 0xffffffff) && ((int)uVar9 < (int)uVar18)) {
      uVar9 = uVar18;
    }
    if ((uVar19 != 0xffffffff) && ((int)uVar9 < (int)uVar19)) {
      uVar9 = uVar19;
    }
    if (0 < iVar21) {
      uVar18 = 0;
      do {
        uVar24 = *(uint *)(iVar6 + uVar18 * 4 + 0x20);
        uVar18 = uVar18 + 1 & 0xff;
        uVar19 = uVar24 & 0x1f;
        if (uVar24 != 0xffffffff) {
          uVar25 = uVar24 + 0x1f;
          if (-1 < (int)uVar24) {
            uVar25 = uVar24;
          }
          if (-1 < (int)-uVar24) {
            uVar19 = -(-uVar24 & 0x1f);
          }
          if ((int)uVar9 < (int)uVar24) {
            uVar9 = uVar24;
          }
          local_278[(int)uVar25 >> 5] = local_278[(int)uVar25 >> 5] | 1 << (uVar19 & 0xff);
        }
      } while ((int)uVar18 < iVar21);
    }
    psVar29 = &local_3c8;
    local_3c4 = 0;
    local_3c8 = 0x14;
    iVar21 = sigwrap_select(uVar9 + 1,local_278,0,0,psVar29);
    if (iVar21 == -1) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_000155d0,DAT_000156d4,DAT_000155cc);
      if (*(int *)(DAT_000155d4 + 0x1e8) == 1 && bVar27) {
        sigwrap_close(local_3f8);
      }
      if (*(int *)(DAT_000155d4 + 0x1e4) == 1 && bVar28) {
        sigwrap_close(local_3ec);
      }
      puVar20 = DAT_0001567c;
      sigwrap_close(*DAT_0001567c);
      sigwrap_close(puVar20[1]);
      return 0;
    }
    if (0 < *(int *)(iVar4 + 0x10)) {
      unaff_r6 = (socklen_t *)0x0;
      do {
        iVar26 = (int)unaff_r6 * 4;
        if (*(int *)(iVar4 + iVar26 + 0x94) != 0) {
          iVar17 = iVar6 + iVar26;
          uVar19 = *(uint *)(iVar17 + 0x20);
          uVar18 = uVar19 + 0x1f;
          if (-1 < (int)uVar19) {
            uVar18 = uVar19;
          }
          uVar9 = uVar19 & 0x1f;
          if (-1 < (int)-uVar19) {
            uVar9 = -(-uVar19 & 0x1f);
          }
          if (((local_278[(int)uVar18 >> 5] & 1 << (uVar9 & 0xff)) == 0) &&
             (*(int *)(iVar4 + iVar26 + 0x50) == 0)) {
            if ((*(int *)(iVar17 + 0x10) < 1) || (iVar23 = sysinfo(&local_378), iVar23 != 0)) {
              if (iVar21 == 0) goto LAB_00014a10;
            }
            else {
              difftime(local_378.uptime,*(time_t *)(iVar17 + 0x10));
              if ((iVar21 == 0) || (iVar17 = FUN_00018f2c(), iVar17 != 0)) {
LAB_00014a10:
                psVar29 = unaff_r6;
                IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0001551c,DAT_000156d4,DAT_00015518,unaff_r6);
                if (*(int *)(iVar4 + iVar26 + 0xd4) == 1) {
                  switch(*(undefined4 *)(iVar4 + iVar26 + 0x80)) {
                  case 0:
                    iVar17 = FUN_000138ec(2,unaff_r6);
                    if (iVar17 == 0) {
                      FUN_00013a74(*(undefined4 *)(iVar6 + iVar26 + 0x20),unaff_r6,0xf3);
                    }
                    else {
LAB_00014e40:
                      IDBG_LINUXAPP_DbgOut(0x82,DAT_000155e0,DAT_000156d4,0x3bc);
                    }
                    break;
                  case 1:
                    iVar26 = FUN_0001397c(unaff_r6);
                    if (iVar26 == 0) {
                      iVar26 = FUN_000138ec(1,unaff_r6);
                      goto joined_r0x00014e3c;
                    }
LAB_00015188:
                    iVar26 = FUN_000138ec(3,unaff_r6);
                    if (iVar26 != 0) goto LAB_00014e40;
                    FUN_00013f58(unaff_r6,1);
                    break;
                  case 2:
                    iVar26 = FUN_0001397c(unaff_r6);
                    if (iVar26 != 0) goto LAB_00015188;
                    iVar26 = FUN_000138ec(2,unaff_r6);
joined_r0x00014e3c:
                    if (iVar26 != 0) goto LAB_00014e40;
                    break;
                  case 3:
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00015524,DAT_000156d4,DAT_00015520);
                    break;
                  default:
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_000156cc,DAT_000156d4,DAT_000156c8);
                  }
                }
              }
            }
          }
        }
        unaff_r6 = (socklen_t *)((int)unaff_r6 + 1U & 0xff);
      } while ((int)unaff_r6 < *(int *)(iVar4 + 0x10));
    }
    uVar19 = *(uint *)(iVar6 + 0x30);
    uVar18 = *(uint *)(iVar6 + 0x34);
    if (uVar19 == 0xffffffff) {
LAB_00014eec:
      if (uVar18 != 0xffffffff) {
        uVar19 = uVar18 & 0x1f;
        if (-1 < (int)-uVar18) {
          uVar19 = -(-uVar18 & 0x1f);
        }
        uVar9 = uVar18 + 0x1f;
        if (-1 < (int)uVar18) {
          uVar9 = uVar18;
        }
        if ((local_278[(int)uVar9 >> 5] & 1 << (uVar19 & 0xff)) != 0) {
          bVar3 = false;
LAB_00014b20:
          sVar10 = WaitForClientConnection(uVar18);
          goto LAB_00014b28;
        }
      }
LAB_00014f38:
      if (0 < *(int *)(iVar4 + 0x10)) {
        psVar22 = (socklen_t *)0x0;
        do {
          iVar21 = (int)psVar22 * 4;
          unaff_r6 = (socklen_t *)(iVar6 + iVar21);
          uVar18 = unaff_r6[8];
          if (uVar18 != 0xffffffff) {
            uVar19 = uVar18 + 0x1f;
            if (-1 < (int)uVar18) {
              uVar19 = uVar18;
            }
            uVar9 = uVar18 & 0x1f;
            if (-1 < (int)-uVar18) {
              uVar9 = -(-uVar18 & 0x1f);
            }
            if ((local_278[(int)uVar19 >> 5] & 1 << (uVar9 & 0xff)) == 0) goto LAB_00014f50;
            iVar26 = sysinfo(&local_378);
            if (iVar26 == 0) {
              unaff_r6[4] = local_378.uptime;
            }
            unaff_r6 = *(socklen_t **)(DAT_000155e4 + (int)psVar22 * 4);
            uVar13 = *(undefined4 *)(iVar6 + iVar21 + 0x20);
            iVar17 = iVar4 + iVar21;
            *(undefined4 *)(iVar17 + 0x424) = 0;
            iVar26 = FUN_000167e0(uVar13,unaff_r6,0x14);
            if (iVar26 == 1) {
              iVar26 = FUN_000133cc(psVar22);
              if (iVar26 != 0) {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000156b8,DAT_000156d4,DAT_000155d8);
              }
              goto LAB_00015264;
            }
            cVar2 = *(char *)((int)unaff_r6 + 0x29);
            if (cVar2 != -0xd) {
              if (cVar2 == -9) {
                psVar29 = psVar22;
                IDBG_LINUXAPP_DbgOut
                          (0x84,DAT_000155b0,DAT_000156d4,0x1f8,psVar22,
                           DAT_000155ac + (int)psVar22 * 0x40);
LAB_00015264:
                pvVar14 = (void *)(uint)local_3d0;
                iVar26 = (int)pvVar14 * 4;
                if ((((*(int *)(iVar4 + iVar26 + 0x50) == 0) &&
                     (*(int *)(iVar6 + iVar26 + 0x38) != 3)) && (*(int *)(DAT_000155d4 + 0x60) != 1)
                    ) && (*(int *)(iVar4 + iVar26 + 0xb4) == 0)) {
                  iVar23 = 1;
LAB_000152ac:
                  local_3d4 = (socklen_t *)
                              pthread_create((pthread_t *)(DAT_00015548 + iVar26),
                                             (pthread_attr_t *)0x0,DAT_0001554c,pvVar14);
                  if (local_3d4 == (socklen_t *)0x0) {
                    *(undefined4 *)(iVar4 + (uint)local_3d0 * 4 + 0xb4) = 1;
                  }
                  else {
                    piVar15 = __errno_location();
                    psVar29 = local_3d4;
                    IDBG_LINUXAPP_DbgOut
                              (0x82,DAT_0001566c,DAT_000156d4,DAT_00015614,local_3d4,*piVar15);
                  }
LAB_000152dc:
                  if (iVar23 != 1) {
LAB_00015248:
                    if (iVar23 == 3) goto LAB_00014f50;
                    goto LAB_00015034;
                  }
                }
                FUN_00013f58(psVar22,1);
                goto LAB_00014f50;
              }
              if (cVar2 == -8) {
                iVar26 = *(int *)(iVar4 + 0x10);
                *(undefined4 *)(iVar6 + iVar21 + 0x38) = *(undefined4 *)((int)unaff_r6 + 0x3e);
                if (iVar26 < (int)psVar22) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_0001568c,DAT_000156d4,DAT_00015688,psVar22);
                }
                else {
                  memset(local_174,0,DAT_00015590);
                  local_174 = *(undefined1 (*) [4])((int)unaff_r6 + 0x3e);
                  if (local_174 == (undefined1  [4])0x1) {
                    *(uint *)(iVar17 + 0x50) = (uint)psVar22 | 0x200;
                  }
                  snprintf(acStack_168,0x100,DAT_00015594,(int)unaff_r6 + 0x42);
                  local_170 = psVar22;
                  uVar18 = snprintf(acStack_68,0x3f,DAT_00015594,DAT_000155ac + (int)psVar22 * 0x40)
                  ;
                  if (uVar18 < 0x3f) {
                    unaff_r6 = *(socklen_t **)(iVar4 + (int)psVar22 * 4);
                    local_16c = 1;
                    if (unaff_r6 == (socklen_t *)0x1b) {
                      updateProcessPriority(1,local_174);
                      local_16c = 0x1b;
                    }
                    iVar26 = setRedirectedMediaInfo(1,local_174);
                    if (iVar26 == 0) {
                      pvVar14 = (void *)(uint)local_3d0;
                      iVar26 = (int)pvVar14 * 4;
                      if ((*(int *)(iVar4 + iVar26 + 0x50) != 0) ||
                         (*(int *)(iVar6 + iVar26 + 0x38) == 3)) goto LAB_00014f50;
                      iVar23 = 3;
                      goto LAB_00015238;
                    }
                    IDBG_LINUXAPP_DbgOut(0x84,DAT_000156a4,DAT_000156d4,0xa70,psVar22);
                  }
                  else {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_000156b8,DAT_000156d4,0xa60);
                  }
                }
                psVar29 = psVar22;
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00015694,DAT_000156d4,DAT_00015690,psVar22);
                goto LAB_00015264;
              }
              pvVar14 = (void *)(uint)local_3d0;
              iVar26 = (int)pvVar14 * 4;
              if ((*(int *)(iVar4 + iVar26 + 0x50) == 0) &&
                 (iVar23 = 0, *(int *)(iVar6 + iVar26 + 0x38) != 3)) {
LAB_00015238:
                if (*(int *)(DAT_000155d4 + 0x60) != 1) {
                  if (*(int *)(iVar4 + iVar26 + 0xb4) == 0) goto LAB_000152ac;
                  goto LAB_000152dc;
                }
                goto LAB_00015248;
              }
LAB_00015034:
              iVar17 = iVar4 + iVar21;
              iVar26 = *(int *)(iVar17 + 0xd4);
              if (*(int *)(iVar17 + 0x424) == 1) goto LAB_000151fc;
              if (iVar26 != 1) goto LAB_00014f50;
              switch(*(undefined4 *)(iVar17 + 0x80)) {
              case 0:
                IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00015558,DAT_000156d4,DAT_00015554);
              case 1:
                iVar21 = FUN_000138ec(0,psVar22);
                break;
              case 2:
                iVar21 = FUN_000138ec(2,psVar22);
                break;
              case 3:
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000155b8,DAT_000156d4,DAT_000155b4,psVar29);
                iVar21 = FUN_000138ec(3,psVar22);
                if (iVar21 == 0) goto LAB_00014f50;
                goto LAB_00015098;
              default:
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000156d8,DAT_000156d4,DAT_000156d0,psVar29);
                goto LAB_00014f50;
              }
              if ((iVar21 != 0) || (iVar21 = FUN_00013868(psVar22), iVar21 != 0)) {
LAB_00015098:
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000155e0,DAT_000156d4,0x318);
              }
              goto LAB_00014f50;
            }
            IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0001556c,DAT_000156d4,DAT_00015568);
            pvVar14 = (void *)(uint)local_3d0;
            *(undefined4 *)(iVar17 + 0x424) = 1;
            iVar26 = (int)pvVar14 * 4;
            if (*(int *)(iVar4 + iVar26 + 0x50) == 0) {
              iVar23 = 0;
              if (*(int *)(iVar6 + iVar26 + 0x38) != 3) goto LAB_00015238;
              iVar26 = *(int *)(iVar17 + 0xd4);
            }
            else {
              iVar26 = *(int *)(iVar17 + 0xd4);
            }
LAB_000151fc:
            if (iVar26 != 1) goto LAB_00014f50;
            switch(*(undefined4 *)(iVar4 + iVar21 + 0x80)) {
            case 0:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000155c0,DAT_000156d4,DAT_000155bc);
            case 2:
              iVar21 = FUN_000138ec(0,psVar22);
              break;
            case 1:
              iVar21 = FUN_000138ec(1,psVar22);
              break;
            case 3:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000155c8,DAT_000156d4,0x344);
              iVar21 = FUN_000138ec(3,psVar22);
              if (iVar21 == 0) goto LAB_00014f50;
              goto LAB_00015988;
            default:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000156bc,DAT_000156d4,0x34c);
              goto LAB_00014f50;
            }
            if ((iVar21 != 0) || (iVar21 = FUN_00013868(psVar22), iVar21 != 0)) {
LAB_00015988:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000155e0,DAT_000156d4,DAT_000155c4);
            }
          }
LAB_00014f50:
          psVar22 = (socklen_t *)((int)psVar22 + 1U & 0xff);
        } while ((int)psVar22 < *(int *)(iVar4 + 0x10));
      }
      uVar19 = *DAT_0001567c;
      uVar18 = uVar19 + 0x1f;
      if (-1 < (int)uVar19) {
        uVar18 = uVar19;
      }
      uVar9 = uVar19 & 0x1f;
      if (-1 < (int)-uVar19) {
        uVar9 = -(-uVar19 & 0x1f);
      }
      if ((local_278[(int)uVar18 >> 5] & 1 << (uVar9 & 0xff)) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00015574,DAT_000156d4,DAT_00015570);
        unaff_r6 = &local_3cc;
        iVar21 = sigwrap_read(*DAT_0001567c,&local_3ce,2);
        if (iVar21 != 2) {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_0001561c,DAT_000156d4,DAT_000155dc);
          goto LAB_0001476c;
        }
        uVar18 = (uint)local_3ce;
        if (*(int *)(iVar4 + 0x10) <= (int)uVar18) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000156b8,DAT_000156d4,0x660);
          if (*(int *)(DAT_0001569c + 0x1e8) == 1 && bVar27) {
            sigwrap_close(local_3f8);
          }
          if (*(int *)(DAT_0001569c + 0x1e4) == 1 && bVar28) {
            sigwrap_close(local_3ec);
          }
          puVar20 = DAT_0001567c;
          sigwrap_close(*DAT_0001567c);
          sigwrap_close(puVar20[1]);
          return 1;
        }
        iVar21 = iVar4 + uVar18 * 4;
        *(undefined4 *)(iVar21 + 0xa4) = 0;
        if (*(int *)(iVar21 + 0x94) == 0) goto LAB_0001476c;
        uVar18 = uVar18 & 0xff;
        iVar21 = iVar4 + uVar18 * 4;
        if (*(int *)(iVar21 + 0xd4) != 1) goto LAB_00015ae8;
        switch(*(undefined4 *)(iVar21 + 0x80)) {
        case 0:
        case 2:
LAB_00015ac4:
          iVar21 = FUN_000138ec(1,uVar18);
          if (iVar21 != 0) {
LAB_00015ad4:
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000155e0,DAT_000156d4,0x380);
          }
          break;
        case 1:
          iVar21 = FUN_0001397c(uVar18);
          if (iVar21 == 0) goto LAB_00015ac4;
          iVar21 = FUN_000138ec(3,uVar18);
          if (iVar21 != 0) goto LAB_00015ad4;
          goto LAB_00015b5c;
        case 3:
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00015630,DAT_000156d4,DAT_0001562c);
          break;
        default:
          IDBG_LINUXAPP_DbgOut(0x82,DAT_000156c4,DAT_000156d4,DAT_000156c0);
        }
LAB_00015ae8:
        iVar21 = *(int *)(iVar6 + (uint)local_3ce * 4 + 0x20);
        if (iVar21 != -1) {
          uVar18 = local_3ce & 0xff;
          if ((int)uVar18 < *(int *)(iVar4 + 0x10)) {
            pvVar14 = memcpy(*(void **)(DAT_000155e4 + uVar18 * 4),
                             *(void **)(DAT_000155e4 + uVar18 * 4 + 0x10),0x3e);
            *(undefined1 *)((int)pvVar14 + 0x35) = 0;
            *(undefined1 *)((int)pvVar14 + 0x36) = 0;
            *(undefined1 *)((int)pvVar14 + 0x37) = 0;
            *(undefined1 *)((int)pvVar14 + 0x38) = 0;
            *(undefined1 *)((int)pvVar14 + 0x39) = 0;
            *(undefined1 *)((int)pvVar14 + 0x3a) = 0;
            *(undefined1 *)((int)pvVar14 + 0x3b) = 0;
            *(undefined1 *)((int)pvVar14 + 0x3c) = 0;
            iVar21 = FUN_00013494(iVar21,uVar18);
            if (iVar21 == 0) goto LAB_000150f0;
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000156b8,DAT_000156d4,DAT_00015670);
          }
LAB_00015b5c:
          FUN_00013f58((undefined1)local_3ce,1);
          goto LAB_0001476c;
        }
      }
LAB_000150f0:
      if ((*(int *)(DAT_000155d4 + 0x1e4) == 1 && bVar28) && ((uVar7 & local_278[iVar8]) != 0)) {
        iVar21 = sigwrap_read(local_3ec,local_174,5);
        if (iVar21 != 5) {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_0001561c,DAT_000156d4,DAT_00015618);
          goto LAB_0001476c;
        }
        uVar18 = Get_index_to_racsessionid
                           (DAT_00015598,*(undefined4 *)(iVar4 + 0x10),
                            (int)local_170 << 0x18 | (uint)local_174 >> 8);
        uVar19 = *(uint *)(iVar4 + uVar18 * 4 + 0x50);
        if (uVar19 == 0) {
          FUN_00013a74(*(undefined4 *)(iVar6 + uVar18 * 4 + 0x20),uVar18 & 0xff,0xf6);
        }
        else {
          local_3c0 = 400;
          uVar13 = DAT_0001559c;
          if ((uVar19 & 0x200) == 0) {
            uVar13 = DAT_000155a0;
          }
          local_3b8 = 1;
          local_3bc = uVar18;
          WriteDataInMediaPipe(uVar13,&local_3c0);
        }
        sleep(3);
        FUN_00013f58(uVar18 & 0xff,1);
      }
      if ((*(int *)(DAT_000155d4 + 0x1e8) == 1 && bVar27) && ((uVar16 & local_278[iVar1]) != 0)) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_0001555c);
        iVar21 = sigwrap_read(local_3f8,local_2b8,1);
        if (iVar21 == 1) {
          iVar21 = GetVMediaCfg(local_174,*(undefined4 *)(DAT_0001569c + 0x68),
                                *(undefined4 *)(DAT_0001569c + 0x74),
                                *(undefined4 *)(DAT_0001569c + 0x180));
          if ((iVar21 == 0) && (local_16c != 0)) {
            local_3d8 = local_3d8 + 1;
            if (local_3d8 != 1) {
              uVar18 = 0;
              while( true ) {
                uVar19 = uVar18 & 0xff;
                unaff_r6 = (socklen_t *)(iVar6 + uVar19 * 4);
                if (*(int *)(iVar4 + 0x10) <= (int)uVar19) break;
                uVar18 = uVar18 + 1;
                if (unaff_r6[8] != 0xffffffff) {
                  shutdown(unaff_r6[8],2);
                  sigwrap_close(unaff_r6[8]);
                  unaff_r6[8] = 0xffffffff;
                }
                FUN_00013f58(uVar19,1);
              }
              if (*(int *)(iVar6 + 0x30) != -1) {
                ShutDownServer();
              }
              if (*(int *)(iVar6 + 0x34) != -1) {
                ShutDownServer();
              }
              iVar21 = DAT_0001569c;
              iVar26 = GetVMediaCfg(local_174,*(undefined4 *)(DAT_0001569c + 0x68),
                                    *(undefined4 *)(DAT_0001569c + 0x74),
                                    *(undefined4 *)(DAT_0001569c + 0x180));
              if (iVar26 == 0) {
                local_16c = iVar26;
                iVar21 = SetVMediaCfg(local_174,*(undefined4 *)(iVar21 + 0x68),
                                      *(undefined4 *)(iVar21 + 0x74),*(undefined4 *)(iVar21 + 0x180)
                                     );
                if (iVar21 != 0) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_000156ac,DAT_000156d4,DAT_000156a8);
                }
              }
              else {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000156b4,DAT_000156d4,DAT_000156b0);
              }
              puts(DAT_00015628);
            }
          }
          else {
            local_3d8 = 0;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_00015564,DAT_000156d4,DAT_00015560);
        }
      }
      goto LAB_0001476c;
    }
    uVar9 = uVar19 + 0x1f;
    if (-1 < (int)uVar19) {
      uVar9 = uVar19;
    }
    uVar24 = uVar19 & 0x1f;
    if (-1 < (int)-uVar19) {
      uVar24 = -(-uVar19 & 0x1f);
    }
    if ((local_278[(int)uVar9 >> 5] & 1 << (uVar24 & 0xff)) == 0) goto LAB_00014eec;
    if (uVar18 != 0xffffffff) {
      uVar9 = uVar18 & 0x1f;
      if (-1 < (int)-uVar18) {
        uVar9 = -(-uVar18 & 0x1f);
      }
      uVar24 = uVar18 + 0x1f;
      if (-1 < (int)uVar18) {
        uVar24 = uVar18;
      }
      if ((local_278[(int)uVar24 >> 5] & 1 << (uVar9 & 0xff)) == 0) goto LAB_00014b08;
      if (*(int *)(DAT_000155d4 + 0x60) == 1) goto LAB_000157f8;
      bVar3 = true;
      goto LAB_00014b20;
    }
LAB_00014b08:
    if (*(int *)(DAT_000155d4 + 0x60) != 1) {
      bVar3 = true;
      uVar18 = uVar19;
      goto LAB_00014b20;
    }
LAB_000157f8:
    sVar10 = WaitForClientConnection_UDS(uVar19);
    bVar3 = true;
LAB_00014b28:
    if (sVar10 == 0xffffffff) goto LAB_00014f38;
    memset(&local_338,0,0x40);
    sVar30 = sVar10;
    IDBG_LINUXAPP_DbgOut(0x84,DAT_0001552c,DAT_000156d4,DAT_00015528,sVar10);
    memset(acStack_2f8,0,0x40);
    unaff_r6 = &local_3cc;
    local_3cc = 0x80;
    iVar21 = getpeername(sVar10,(sockaddr *)local_174,unaff_r6);
    if (iVar21 == 0) {
      if (((uint)local_174 & 0xffff) == 2) {
        inet_ntop(2,&local_170,acStack_2f8,0x40);
      }
      else {
        inet_ntop(10,&local_16c,acStack_2f8,0x40);
        pcVar11 = strchr(acStack_2f8,0x3a);
        if ((pcVar11 != (char *)0x0) && (pcVar11 = strchr(acStack_2f8,0x2e), pcVar11 != (char *)0x0)
           ) {
          __isoc99_sscanf(acStack_2f8,DAT_00015530,local_2b8);
          sVar12 = strlen((char *)local_2b8);
          if (sVar12 == 0x3f) {
            IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000155fc,DAT_000156d4,DAT_000155f8);
          }
          snprintf(acStack_2f8,0x40,DAT_00015594,local_2b8);
        }
      }
      memset(&local_338,0,0x40);
      snprintf((char *)&local_338,0x40,DAT_00015594,acStack_2f8);
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001557c,DAT_000156d4,DAT_00015578,sVar30);
    }
    printf(DAT_00015534,&local_338);
    uVar18 = FUN_00012ec0(sVar10,&local_338,auStack_1f8,&local_3d0);
    printf(DAT_00015538,(uint)local_3d0);
    uVar19 = (uint)local_3d0;
    if ((int)uVar19 < *(int *)(iVar4 + 0x10)) {
      uVar24 = uVar18 - 0x1b;
      uVar9 = uVar18;
      if (uVar18 != 1) {
        uVar9 = uVar24;
      }
      if (uVar9 != 0 && (uVar18 != 1 && uVar24 != 1)) {
        if (uVar18 == 8) {
          iVar21 = FUN_000137a4(sVar10,&local_338,8);
          if (iVar21 != 0) {
            puts(DAT_00015634);
          }
        }
        else {
          if (uVar18 == 4) {
            iVar21 = FUN_000137a4(sVar10,&local_338,4);
          }
          else {
            iVar21 = FUN_000137a4(sVar10,DAT_000155a4,uVar18 & 0xff);
          }
          if (iVar21 != 0) {
            puts(DAT_00015634);
          }
          *(undefined4 *)(iVar4 + (uint)local_3d0 * 4 + 0x40) = 0;
        }
        sleep(3);
        sigwrap_close(sVar10);
      }
      else if (*(int *)(iVar4 + uVar19 * 4 + 0x94) == 1) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00015584,DAT_000156d4,DAT_00015580,uVar19);
        iVar21 = FUN_000137a4(sVar10,DAT_000155ac + (uint)local_3d0 * 0x40,4);
        if (iVar21 != 0) {
          puts(DAT_00015634);
        }
      }
      else {
        snprintf((char *)(DAT_0001553c + uVar19 * 0x81),0x81,DAT_00015594,auStack_1f8);
        iVar21 = FUN_00012e7c();
        if (iVar21 != 0) {
          FUN_0001750c();
        }
        uVar19 = uVar18;
        if (uVar18 != 1) {
          uVar19 = uVar24;
        }
        *(undefined4 *)(iVar4 + (uint)local_3d0 * 4 + 0x94) = 1;
        if ((uVar19 == 0 || (uVar18 == 1 || uVar24 == 1)) &&
           (iVar21 = FUN_000137a4(sVar10,DAT_000155a4,uVar18 & 0xff), iVar21 != 0)) {
          puts(DAT_000155a8);
        }
        if (*(int *)(DAT_000155d4 + 0x180) == 1) {
          iVar21 = ioctl(*(int *)(iVar4 + 0x90),DAT_000155e8,&local_3cf);
          if (iVar21 < 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00015658,DAT_000156d4,DAT_00015654);
          }
          if ((local_3cf == '\0') &&
             (iVar21 = ioctl(*(int *)(iVar4 + 0x90),DAT_000155ec), iVar21 < 0)) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000155f4,DAT_000156d4,DAT_000155f0);
          }
        }
        uVar19 = (uint)local_3d0;
        iVar21 = iVar4 + uVar19 * 0x40;
        *(undefined4 *)(iVar21 + 0x2e8) = local_338;
        *(undefined4 *)(iVar21 + 0x2ec) = uStack_334;
        *(undefined4 *)(iVar21 + 0x2f0) = uStack_330;
        *(undefined4 *)(iVar21 + 0x2f4) = uStack_32c;
        *(undefined4 *)(iVar21 + 0x2f8) = local_328;
        *(undefined4 *)(iVar21 + 0x2fc) = uStack_324;
        *(undefined4 *)(iVar21 + 0x300) = uStack_320;
        *(undefined4 *)(iVar21 + 0x304) = uStack_31c;
        *(undefined4 *)(iVar21 + 0x308) = local_318;
        *(undefined4 *)(iVar21 + 0x30c) = uStack_314;
        *(undefined4 *)(iVar21 + 0x310) = uStack_310;
        *(undefined4 *)(iVar21 + 0x314) = uStack_30c;
        unaff_r6 = (socklen_t *)(iVar6 + uVar19 * 4);
        iVar26 = iVar4 + uVar19 * 4;
        unaff_r6[8] = sVar10;
        *(undefined4 *)(iVar21 + 0x318) = local_308;
        *(undefined4 *)(iVar21 + 0x31c) = uStack_304;
        *(undefined4 *)(iVar21 + 800) = uStack_300;
        *(undefined4 *)(iVar21 + 0x324) = uStack_2fc;
        iVar21 = DAT_000155d4;
        uVar18 = *(uint *)(iVar26 + 0x50);
        if (uVar18 == 0) {
          if ((int)uVar19 < *(int *)(iVar4 + 0x10)) {
            *(undefined4 *)(iVar26 + 0x70) = 0;
            iVar17 = *(int *)(iVar21 + 0x1e4);
            *(undefined4 *)(iVar26 + 0x80) = 0;
            local_2b8[0] = 0;
            *(undefined4 *)(iVar26 + 0xd4) = 1;
            iVar21 = DAT_00015540;
            local_174 = (undefined1  [4])uVar18;
            if (iVar17 != 1) {
              iVar26 = get_service_configurations(DAT_00015544,DAT_00015540);
              if (iVar26 == 0) {
                iVar26 = isNotEditable(iVar21 + 0x2f,1);
                if (iVar26 != 0) {
                  getNotEditableData(iVar21 + 0x2f,1,(sockaddr *)local_174);
                }
                iVar21 = get_active_session(2,local_2b8);
                if (iVar21 != 0) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00015678,DAT_000156d4,DAT_00015664);
                }
                local_2b8[0] = local_2b8[0] + 1;
                if ((int)local_174 < (int)(uint)local_2b8[0]) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00015660,DAT_000156d4,DAT_0001565c);
                }
                else {
                  iVar21 = set_active_session(2);
                  if (iVar21 != 0) {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00015678,DAT_000156d4,0x29c);
                  }
                }
              }
              else {
                puts(DAT_00015624);
              }
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00015620,DAT_000156d4,0x280);
          }
          if (bVar3) {
            iVar21 = pthread_create((pthread_t *)(DAT_00015548 + (int)(uint)local_3d0 * 4),
                                    (pthread_attr_t *)0x0,DAT_0001554c,(void *)(uint)local_3d0);
            if (iVar21 == 0) {
              *(undefined4 *)(iVar4 + (uint)local_3d0 * 4 + 0xb4) = 1;
            }
            else {
              piVar15 = __errno_location();
              IDBG_LINUXAPP_DbgOut(0x82,DAT_0001566c,DAT_000156d4,DAT_00015668,local_3d4,*piVar15);
            }
          }
        }
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_0001558c,DAT_000156d4,DAT_00015588,uVar19);
      sigwrap_close(sVar10);
    }
  } while( true );
}

