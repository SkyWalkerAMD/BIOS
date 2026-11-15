
/* WARNING: Type propagation algorithm not settling */

undefined4 FUN_0001506c(void)

{
  int iVar1;
  char cVar2;
  bool bVar3;
  char *pcVar4;
  bool bVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined4 uVar9;
  void *pvVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  char *pcVar18;
  undefined4 uVar19;
  int iVar20;
  int iVar21;
  int iVar22;
  uint uVar23;
  bool bVar24;
  bool bVar25;
  uint local_320;
  uint local_31c;
  byte local_2f9;
  char local_2f8;
  byte local_2f7;
  ushort local_2f6;
  uint local_2f4;
  void *local_2f0;
  undefined4 local_2ec;
  undefined4 local_2e8;
  undefined1 auStack_2e4 [44];
  sysinfo local_2b8;
  uint local_278 [32];
  undefined1 auStack_1f8 [132];
  uint local_174;
  uint local_170;
  int local_16c;
  undefined4 uStack_168;
  undefined4 local_164;
  undefined4 uStack_160;
  undefined4 uStack_15c;
  undefined4 uStack_158;
  undefined4 local_154;
  undefined4 uStack_150;
  undefined4 uStack_14c;
  undefined4 uStack_148;
  undefined4 local_144;
  undefined4 uStack_140;
  undefined4 uStack_13c;
  undefined4 uStack_138;
  char acStack_68 [68];
  
  iVar6 = GetVMediaCfg(auStack_2e4,*(undefined4 *)(DAT_00016064 + 0x68),
                       *(undefined4 *)(DAT_00016064 + 0x74),*(undefined4 *)(DAT_00016064 + 0x180));
  iVar11 = DAT_00016068;
  if (iVar6 != 0) {
    IDBG_LINUXAPP_DbgOut(0x80,DAT_00016174,DAT_00016190,DAT_00016170);
    return 1;
  }
  uVar17 = 0;
  if (0 < *(int *)(DAT_00016068 + 0x130)) {
    do {
      uVar17 = uVar17 + 1 & 0xff;
    } while ((int)uVar17 < *(int *)(DAT_00016068 + 0x130));
  }
  if (*(int *)(DAT_00016064 + 0x1e8) == 1) {
    iVar6 = mkfifo(DAT_000161a8,DAT_000161a0);
    if (iVar6 == -1) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000161e4,DAT_00016288,DAT_000161e0);
    }
    local_31c = sigwrap_open(DAT_000161a8,DAT_000161a4);
    if (local_31c == 0xffffffff) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_000161b0,DAT_00016288,DAT_000161ac);
      return 1;
    }
  }
  else {
    local_31c = 0xffffffff;
  }
  if (*(int *)(DAT_00016064 + 0x1e4) == 1) {
    iVar6 = mkfifo(DAT_00016168,DAT_000161a0);
    if (iVar6 == -1) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000161e4,DAT_00016288,DAT_000161d4);
    }
    local_320 = sigwrap_open(DAT_00016168,DAT_000161a4);
    if (local_320 == 0xffffffff) {
      IDBG_LINUXAPP_DbgOut(0x84,DAT_0001616c,DAT_00016190,0x4ef);
      if (local_31c == 0xffffffff) {
        return 1;
      }
      sigwrap_close(local_31c);
      return 1;
    }
  }
  else {
    local_320 = 0xffffffff;
  }
  iVar7 = pipe((int *)&local_2f4);
  iVar6 = DAT_0001606c;
  bVar24 = local_31c != 0xffffffff;
  bVar25 = local_320 != 0xffffffff;
  if (iVar7 == 0) {
    uVar9 = DAT_000161fc;
    uVar19 = DAT_000161f8;
    if ((*(uint *)(DAT_0001606c + 0x40) & *(uint *)(DAT_0001606c + 0x44)) != 0xffffffff) {
      uVar17 = local_31c + 0x1f;
      if (-1 < (int)local_31c) {
        uVar17 = local_31c;
      }
      uVar12 = local_31c & 0x1f;
      if (-1 < (int)-local_31c) {
        uVar12 = -(-local_31c & 0x1f);
      }
      uVar14 = local_320 + 0x1f;
      if (-1 < (int)local_320) {
        uVar14 = local_320;
      }
      iVar7 = (int)uVar14 >> 5;
      uVar14 = local_320 & 0x1f;
      if (-1 < (int)-local_320) {
        uVar14 = -(-local_320 & 0x1f);
      }
      uVar12 = 1 << (uVar12 & 0xff);
      iVar1 = (int)uVar17 >> 5;
      uVar17 = 1 << (uVar14 & 0xff);
      bVar5 = false;
LAB_000151b4:
      bVar3 = bVar5;
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00016074,DAT_00016190,DAT_00016070);
      pcVar18 = local_2b8._f + 4;
      do {
        pcVar18 = pcVar18 + 4;
        pcVar18[0] = '\0';
        pcVar18[1] = '\0';
        pcVar18[2] = '\0';
        pcVar18[3] = '\0';
      } while ((uint *)pcVar18 != local_278 + 0x1f);
      uVar14 = *(uint *)(iVar6 + 0x40);
      if (uVar14 != 0xffffffff) {
        uVar15 = uVar14 + 0x1f;
        if (-1 < (int)uVar14) {
          uVar15 = uVar14;
        }
        uVar8 = uVar14 & 0x1f;
        if (-1 < (int)-uVar14) {
          uVar8 = -(-uVar14 & 0x1f);
        }
        local_278[(int)uVar15 >> 5] = local_278[(int)uVar15 >> 5] | 1 << (uVar8 & 0xff);
      }
      uVar15 = *(uint *)(iVar6 + 0x44);
      if (uVar15 != 0xffffffff) {
        uVar8 = uVar15 + 0x1f;
        if (-1 < (int)uVar15) {
          uVar8 = uVar15;
        }
        uVar23 = uVar15 & 0x1f;
        if (-1 < (int)-uVar15) {
          uVar23 = -(-uVar15 & 0x1f);
        }
        local_278[(int)uVar8 >> 5] = local_278[(int)uVar8 >> 5] | 1 << (uVar23 & 0xff);
      }
      iVar20 = *(int *)(DAT_00016064 + 0x1e8);
      uVar8 = local_2f4 + 0x1f;
      if (-1 < (int)local_2f4) {
        uVar8 = local_2f4;
      }
      uVar23 = local_2f4 & 0x1f;
      if (-1 < (int)-local_2f4) {
        uVar23 = -(-local_2f4 & 0x1f);
      }
      local_278[(int)uVar8 >> 5] = local_278[(int)uVar8 >> 5] | 1 << (uVar23 & 0xff);
      if (iVar20 == 1 && bVar24) {
        uVar8 = local_31c | (int)local_31c >> 0x1f;
        local_278[iVar1] = local_278[iVar1] | uVar12;
      }
      else {
        uVar8 = 0xffffffff;
      }
      if (*(int *)(DAT_00016064 + 0x1e4) == 1) {
        if (local_320 != 0xffffffff) {
          if ((int)uVar8 < (int)local_320) {
            uVar8 = local_320;
          }
          local_278[iVar7] = local_278[iVar7] | uVar17;
        }
        clear_invalid_register_session_vmedia(9,DAT_00016164,*(undefined4 *)(iVar11 + 0x130));
        clear_invalid_register_session_vmedia(0xc,DAT_00016164,*(undefined4 *)(iVar11 + 0x130));
        uVar14 = *(uint *)(iVar6 + 0x40);
        uVar15 = *(uint *)(iVar6 + 0x44);
      }
      uVar23 = local_2f4;
      if ((int)local_2f4 <= (int)uVar8) {
        uVar23 = uVar8;
      }
      if ((uVar14 != 0xffffffff) && ((int)uVar23 < (int)uVar14)) {
        uVar23 = uVar14;
      }
      if ((uVar15 != 0xffffffff) && ((int)uVar23 < (int)uVar15)) {
        uVar23 = uVar15;
      }
      iVar20 = *(int *)(iVar11 + 0x130);
      if (0 < iVar20) {
        uVar14 = 0;
        do {
          uVar8 = *(uint *)(iVar6 + uVar14 * 4 + 0x20);
          uVar14 = uVar14 + 1 & 0xff;
          uVar15 = uVar8 & 0x1f;
          if (uVar8 != 0xffffffff) {
            uVar16 = uVar8 + 0x1f;
            if (-1 < (int)uVar8) {
              uVar16 = uVar8;
            }
            if (-1 < (int)-uVar8) {
              uVar15 = -(-uVar8 & 0x1f);
            }
            if ((int)uVar23 < (int)uVar8) {
              uVar23 = uVar8;
            }
            local_278[(int)uVar16 >> 5] = local_278[(int)uVar16 >> 5] | 1 << (uVar15 & 0xff);
          }
        } while ((int)uVar14 < iVar20);
      }
      local_2e8 = 0;
      local_2ec = 0x14;
      iVar20 = sigwrap_select(uVar23 + 1,local_278,0,0,&local_2ec);
      if (iVar20 == -1) {
        IDBG_LINUXAPP_DbgOut(0x84,DAT_00016140,DAT_00016190,DAT_0001613c);
        if (*(int *)(DAT_000161d0 + 0x1e8) == 1 && bVar24) goto LAB_000168c4;
        goto LAB_000163a8;
      }
      if (0 < *(int *)(iVar11 + 0x130)) {
        uVar14 = 0;
        do {
          iVar21 = uVar14 * 4;
          if (*(int *)(iVar11 + iVar21 + 0x1fc) != 0) {
            iVar13 = iVar6 + iVar21;
            uVar8 = *(uint *)(iVar13 + 0x20);
            uVar15 = uVar8 + 0x1f;
            if (-1 < (int)uVar8) {
              uVar15 = uVar8;
            }
            uVar23 = uVar8 & 0x1f;
            if (-1 < (int)-uVar8) {
              uVar23 = -(-uVar8 & 0x1f);
            }
            if (((local_278[(int)uVar15 >> 5] & 1 << (uVar23 & 0xff)) == 0) &&
               (*(int *)(iVar11 + iVar21 + 0x1dc) == 0)) {
              if ((*(int *)(iVar13 + 0x30) < 1) || (iVar22 = sysinfo(&local_2b8), iVar22 != 0)) {
                if (iVar20 == 0) goto LAB_00015454;
              }
              else {
                difftime(local_2b8.uptime,*(time_t *)(iVar13 + 0x30));
                if ((iVar20 == 0) || (iVar13 = FUN_000196d8(), iVar13 != 0)) {
LAB_00015454:
                  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0001607c,DAT_00016190,DAT_00016078,uVar14);
                  if (*(int *)(iVar11 + iVar21 + 0x154) == 1) {
                    switch(*(undefined4 *)(iVar11 + iVar21 + 0x144)) {
                    case 0:
                      iVar13 = FUN_000138c0(2,uVar14);
                      if (iVar13 == 0) {
                        FUN_00013960(*(undefined4 *)(iVar6 + iVar21 + 0x20),uVar14,0xf3);
                      }
                      else {
LAB_000156d8:
                        IDBG_LINUXAPP_DbgOut(0x82,DAT_00016138,DAT_00016190,DAT_000160ac);
                      }
                      break;
                    case 1:
                      iVar21 = FUN_00013b20(uVar14);
                      if (iVar21 != 0) goto LAB_00015bc4;
                      iVar21 = FUN_000138c0(1,uVar14);
joined_r0x000156d4:
                      if (iVar21 != 0) goto LAB_000156d8;
                      break;
                    case 2:
                      iVar21 = FUN_00013b20(uVar14);
                      if (iVar21 == 0) {
                        iVar21 = FUN_000138c0(2,uVar14);
                        goto joined_r0x000156d4;
                      }
LAB_00015bc4:
                      iVar21 = FUN_000138c0(3,uVar14);
                      if (iVar21 != 0) goto LAB_000156d8;
                      puts(DAT_000160f8);
                      FUN_000149e4(uVar14,1);
                      break;
                    case 3:
                      IDBG_LINUXAPP_DbgOut(0x82,DAT_00016084,DAT_00016190,DAT_00016080);
                      break;
                    default:
                      IDBG_LINUXAPP_DbgOut(0x82,DAT_00016280,DAT_00016288,DAT_0001627c);
                    }
                  }
                }
              }
            }
          }
          uVar14 = uVar14 + 1 & 0xff;
        } while ((int)uVar14 < *(int *)(iVar11 + 0x130));
      }
      uVar14 = *(uint *)(iVar6 + 0x40);
      bVar5 = bVar3;
      if (uVar14 != 0xffffffff) {
        uVar15 = uVar14 + 0x1f;
        if (-1 < (int)uVar14) {
          uVar15 = uVar14;
        }
        uVar8 = uVar14 & 0x1f;
        if (-1 < (int)-uVar14) {
          uVar8 = -(-uVar14 & 0x1f);
        }
        if ((local_278[(int)uVar15 >> 5] & 1 << (uVar8 & 0xff)) == 0) goto LAB_0001552c;
        if (*(int *)(DAT_00016064 + 0x60) == 1) {
          iVar20 = WaitForClientConnection_UDS();
          if (iVar20 != -1) goto LAB_00015d00;
          goto LAB_0001552c;
        }
        iVar20 = WaitForClientConnection();
        if (iVar20 == -1) goto LAB_0001552c;
LAB_00015d00:
        memset(&local_174,0,0x40);
        IDBG_LINUXAPP_DbgOut(0x84,DAT_0001608c,DAT_00016190,DAT_00016108,iVar20);
        pcVar18 = DAT_00016090;
        iVar21 = 8;
        do {
          if (*(int *)(iVar11 + 0x220) == 0) goto LAB_00015d64;
          puts(pcVar18);
          sleep(1);
          pcVar4 = DAT_00016094;
          iVar21 = iVar21 + -1;
        } while (iVar21 != 0);
        *(undefined4 *)(iVar11 + 0x220) = 0;
        puts(pcVar4);
LAB_00015d64:
        FUN_00014120(iVar20,&local_174);
        printf(DAT_00016098,&local_174);
        uVar14 = FUN_00013270(iVar20,&local_174,auStack_1f8,&local_2f9,&local_2f7);
        printf(DAT_0001609c,(uint)local_2f9);
        printf(DAT_000160a0,(uint)local_2f7);
        uVar15 = (uint)local_2f9;
        if ((int)uVar15 < *(int *)(iVar11 + 0x130)) {
          if (uVar14 != 1) {
            if (uVar14 == 8) goto LAB_00016350;
            if (uVar14 == 4) {
              iVar21 = FUN_00014090(iVar20,&local_174,4);
            }
            else {
              iVar21 = FUN_00014090(iVar20,DAT_00016150,uVar14 & 0xff);
            }
            uVar9 = DAT_0001610c;
            if (iVar21 != 0) {
              puts(DAT_00016198);
              uVar9 = DAT_0001610c;
            }
            goto LAB_00015684;
          }
          uVar9 = DAT_00016144;
          if (*(int *)(iVar11 + uVar15 * 4 + 0x1fc) == 1) {
LAB_000165f4:
            IDBG_LINUXAPP_DbgOut(0x84,DAT_0001617c,DAT_00016190,uVar9,uVar15);
            iVar20 = FUN_00014090(iVar20,DAT_00016180 + (uint)local_2f9 * 0x40,4);
joined_r0x00016620:
            if (iVar20 != 0) {
              puts(DAT_00016198);
            }
          }
          else {
            if (*(int *)(DAT_000161d0 + 0x180) == 1) {
              iVar21 = ioctl(*(int *)(iVar11 + 0x21c),DAT_000161dc,&local_2f8);
              if (iVar21 < 0) {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00016238,DAT_00016288,DAT_00016234);
              }
              if (local_2f8 == '\0') {
                iVar21 = ioctl(*(int *)(iVar11 + 0x21c),DAT_00016230);
                if (iVar21 < 0) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016240,DAT_00016288,DAT_0001623c);
                }
                sleep(2);
              }
              uVar15 = (uint)local_2f9;
            }
            snprintf((char *)(DAT_00016148 + uVar15 * 0x81),0x81,DAT_0001614c,auStack_1f8);
            *(undefined4 *)(iVar11 + (uint)local_2f9 * 4 + 0x1fc) = 1;
            *(byte *)(iVar11 + (uint)local_2f9 + 0x538) = local_2f7;
            iVar21 = FUN_000130b4();
            uVar14 = (uint)local_2f9;
            if ((iVar21 != 0) && (*(char *)(iVar11 + uVar14 + 0x538) != '\0')) {
              FUN_00017d8c();
              uVar14 = (uint)local_2f9;
            }
            iVar21 = FUN_00014090(iVar20,DAT_00016150,1,uVar14);
            if (iVar21 != 0) {
              puts(DAT_0001619c);
            }
            uVar14 = (uint)local_2f9;
            iVar21 = iVar11 + uVar14 * 0x40;
            *(uint *)(iVar21 + 0x438) = local_174;
            *(uint *)(iVar21 + 0x43c) = local_170;
            *(int *)(iVar21 + 0x440) = local_16c;
            *(undefined4 *)(iVar21 + 0x444) = uStack_168;
            *(undefined4 *)(iVar21 + 0x448) = local_164;
            *(undefined4 *)(iVar21 + 0x44c) = uStack_160;
            *(undefined4 *)(iVar21 + 0x450) = uStack_15c;
            *(undefined4 *)(iVar21 + 0x454) = uStack_158;
            *(undefined4 *)(iVar21 + 0x458) = local_154;
            *(undefined4 *)(iVar21 + 0x45c) = uStack_150;
            *(undefined4 *)(iVar21 + 0x460) = uStack_14c;
            *(undefined4 *)(iVar21 + 0x464) = uStack_148;
            *(int *)(iVar6 + uVar14 * 4 + 0x20) = iVar20;
            *(undefined4 *)(iVar21 + 0x468) = local_144;
            *(undefined4 *)(iVar21 + 0x46c) = uStack_140;
            *(undefined4 *)(iVar21 + 0x470) = uStack_13c;
            *(undefined4 *)(iVar21 + 0x474) = uStack_138;
            if (*(int *)(iVar11 + uVar14 * 4 + 0x1dc) == 0) {
              FUN_000130f8(uVar14);
              if (local_2f9 == 0) {
                iVar20 = pthread_create(DAT_0001620c,(pthread_attr_t *)0x0,DAT_00016208,local_2f0);
                if (iVar20 == 1) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016214,DAT_00016288,DAT_00016210);
                }
              }
              else if (local_2f9 == 1) {
                iVar20 = pthread_create(DAT_00016248,(pthread_attr_t *)0x0,DAT_00016244,local_2f0);
                if (iVar20 == 1) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016250,DAT_00016288,DAT_0001624c);
                }
              }
              else if (local_2f9 == 2) {
                iVar20 = pthread_create(DAT_00016224,(pthread_attr_t *)0x0,DAT_00016220,local_2f0);
                if (iVar20 == 1) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_0001622c,DAT_00016288,DAT_00016228);
                }
              }
              else if ((local_2f9 == 3) &&
                      (iVar20 = pthread_create(DAT_00016158,(pthread_attr_t *)0x0,DAT_00016154,
                                               local_2f0), iVar20 == 1)) {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00016160,DAT_00016190,DAT_0001615c);
              }
            }
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_00016188,DAT_00016190,DAT_00016184,uVar15);
        }
        goto LAB_000151b4;
      }
LAB_0001552c:
      uVar14 = *(uint *)(iVar6 + 0x44);
      if (uVar14 != 0xffffffff) {
        uVar15 = uVar14 + 0x1f;
        if (-1 < (int)uVar14) {
          uVar15 = uVar14;
        }
        uVar8 = uVar14 & 0x1f;
        if (-1 < (int)-uVar14) {
          uVar8 = -(-uVar14 & 0x1f);
        }
        if (((local_278[(int)uVar15 >> 5] & 1 << (uVar8 & 0xff)) != 0) &&
           (iVar20 = WaitForClientConnection(), iVar20 != -1)) {
          memset(&local_174,0,0x40);
          IDBG_LINUXAPP_DbgOut(0x84,DAT_0001608c,DAT_00016190,DAT_00016088,iVar20);
          pcVar18 = DAT_00016090;
          iVar21 = 8;
          do {
            if (*(int *)(iVar11 + 0x220) == 0) goto LAB_000155e4;
            puts(pcVar18);
            sleep(1);
            pcVar4 = DAT_00016094;
            iVar21 = iVar21 + -1;
          } while (iVar21 != 0);
          *(undefined4 *)(iVar11 + 0x220) = 0;
          puts(pcVar4);
LAB_000155e4:
          FUN_00014120(iVar20,&local_174);
          printf(DAT_00016098,&local_174);
          uVar14 = FUN_00013270(iVar20,&local_174,auStack_1f8,&local_2f9,&local_2f7);
          printf(DAT_0001609c,(uint)local_2f9);
          printf(DAT_000160a0,(uint)local_2f7);
          uVar15 = (uint)local_2f9;
          if ((int)uVar15 < *(int *)(iVar11 + 0x130)) {
            if (uVar14 == 1) {
              uVar9 = DAT_00016178;
              if (*(int *)(iVar11 + uVar15 * 4 + 0x1fc) == 1) goto LAB_000165f4;
              if (*(int *)(DAT_00016064 + 0x180) == 1) {
                iVar21 = ioctl(*(int *)(iVar11 + 0x21c),DAT_000161dc,&local_2f8);
                if (iVar21 < 0) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016238,DAT_00016288,DAT_00016204);
                }
                if (local_2f8 == '\0') {
                  iVar21 = ioctl(*(int *)(iVar11 + 0x21c),DAT_00016230);
                  if (iVar21 < 0) {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016240,DAT_00016288,DAT_0001621c);
                  }
                  sleep(2);
                }
                uVar15 = (uint)local_2f9;
              }
              snprintf((char *)(DAT_00016148 + uVar15 * 0x81),0x81,DAT_0001614c,auStack_1f8);
              *(undefined4 *)(iVar11 + (uint)local_2f9 * 4 + 0x1fc) = 1;
              *(byte *)(iVar11 + (uint)local_2f9 + 0x538) = local_2f7;
              iVar21 = FUN_000130b4();
              uVar14 = (uint)local_2f9;
              if ((iVar21 != 0) && (*(char *)(iVar11 + uVar14 + 0x538) != '\0')) {
                FUN_00017d8c();
                uVar14 = (uint)local_2f9;
              }
              iVar21 = FUN_00014090(iVar20,DAT_00016150,1,uVar14);
              if (iVar21 != 0) {
                puts(DAT_0001619c);
              }
              uVar14 = (uint)local_2f9;
              iVar21 = iVar11 + uVar14 * 0x40;
              *(uint *)(iVar21 + 0x438) = local_174;
              *(uint *)(iVar21 + 0x43c) = local_170;
              *(int *)(iVar21 + 0x440) = local_16c;
              *(undefined4 *)(iVar21 + 0x444) = uStack_168;
              *(undefined4 *)(iVar21 + 0x448) = local_164;
              *(undefined4 *)(iVar21 + 0x44c) = uStack_160;
              *(undefined4 *)(iVar21 + 0x450) = uStack_15c;
              *(undefined4 *)(iVar21 + 0x454) = uStack_158;
              *(undefined4 *)(iVar21 + 0x458) = local_154;
              *(undefined4 *)(iVar21 + 0x45c) = uStack_150;
              *(undefined4 *)(iVar21 + 0x460) = uStack_14c;
              *(undefined4 *)(iVar21 + 0x464) = uStack_148;
              *(int *)(iVar6 + uVar14 * 4 + 0x20) = iVar20;
              *(undefined4 *)(iVar21 + 0x468) = local_144;
              *(undefined4 *)(iVar21 + 0x46c) = uStack_140;
              *(undefined4 *)(iVar21 + 0x470) = uStack_13c;
              *(undefined4 *)(iVar21 + 0x474) = uStack_138;
              if (*(int *)(iVar11 + uVar14 * 4 + 0x1dc) == 0) {
                FUN_000130f8(uVar14);
                if (local_2f9 == 0) {
                  iVar20 = pthread_create(DAT_0001620c,(pthread_attr_t *)0x0,DAT_00016208,local_2f0)
                  ;
                  if (iVar20 == 1) {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016214,DAT_00016288,DAT_000161d8);
                  }
                }
                else if (local_2f9 == 1) {
                  iVar20 = pthread_create(DAT_00016248,(pthread_attr_t *)0x0,DAT_00016244,local_2f0)
                  ;
                  if (iVar20 == 1) {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016250,DAT_00016288,DAT_00016200);
                  }
                }
                else if (local_2f9 == 2) {
                  iVar20 = pthread_create(DAT_00016224,(pthread_attr_t *)0x0,DAT_00016220,local_2f0)
                  ;
                  if (iVar20 == 1) {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001622c,DAT_00016288,DAT_00016218);
                  }
                }
                else if ((local_2f9 == 3) &&
                        (iVar20 = pthread_create(DAT_00016158,(pthread_attr_t *)0x0,DAT_00016154,
                                                 local_2f0), iVar20 == 1)) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016160,DAT_00016190,DAT_00016124);
                }
              }
            }
            else {
              if (uVar14 == 8) {
LAB_00016350:
                iVar20 = FUN_00014090(iVar20,&local_174,uVar14);
                goto joined_r0x00016620;
              }
              if (uVar14 == 4) {
                iVar21 = FUN_00014090(iVar20,&local_174,4);
                uVar9 = DAT_000160a4;
              }
              else {
                iVar21 = FUN_00014090(iVar20,DAT_00016150,uVar14 & 0xff);
                uVar9 = DAT_000160a4;
              }
              DAT_000160a4 = uVar9;
              if (iVar21 != 0) {
                puts(DAT_00016198);
                uVar9 = DAT_000160a4;
              }
LAB_00015684:
              IDBG_LINUXAPP_DbgOut(0x84,DAT_000160a8,DAT_00016190,uVar9,local_2f9,uVar14);
              *(undefined4 *)(iVar11 + (uint)local_2f9 * 4 + 0x1cc) = 0;
              sleep(3);
              sigwrap_close(iVar20);
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x84,DAT_00016188,DAT_00016190,DAT_00016128,uVar15);
          }
          goto LAB_000151b4;
        }
      }
      if (0 < *(int *)(iVar11 + 0x130)) {
        uVar14 = 0;
        do {
          iVar20 = uVar14 * 4;
          uVar15 = *(uint *)(iVar6 + iVar20 + 0x20);
          if (uVar15 != 0xffffffff) {
            uVar8 = uVar15 + 0x1f;
            if (-1 < (int)uVar15) {
              uVar8 = uVar15;
            }
            uVar23 = uVar15 & 0x1f;
            if (-1 < (int)-uVar15) {
              uVar23 = -(-uVar15 & 0x1f);
            }
            if ((local_278[(int)uVar8 >> 5] & 1 << (uVar23 & 0xff)) == 0) goto LAB_0001579c;
            iVar21 = sysinfo(&local_2b8);
            uVar9 = DAT_00016190;
            if (iVar21 == 0) {
              *(long *)(iVar6 + iVar20 + 0x30) = local_2b8.uptime;
            }
            IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000160b4,uVar9,DAT_000160b8);
            iVar13 = *(int *)(DAT_000160bc + uVar14 * 4);
            uVar9 = *(undefined4 *)(iVar6 + iVar20 + 0x20);
            iVar22 = iVar11 + iVar20;
            *(undefined4 *)(iVar22 + 0x53c) = 0;
            iVar21 = FUN_00017054(uVar9,iVar13,0x14);
            if (iVar21 == 1) {
              iVar20 = FUN_00013770(uVar14);
              if (iVar20 == 0) {
                FUN_00012e68(uVar14);
              }
              else {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000160e8,DAT_00016190,0x234);
              }
              goto LAB_00015b28;
            }
            cVar2 = *(char *)(iVar13 + 0x29);
            if (cVar2 != -0xd) {
              if (cVar2 == -9) {
                IDBG_LINUXAPP_DbgOut
                          (0x84,DAT_00016114,DAT_00016190,DAT_00016110,uVar14,
                           DAT_00016180 + uVar14 * 0x40);
                if (*(int *)(iVar6 + uVar14 * 4) != -1) {
                  FUN_000180b4();
                  *(undefined4 *)(iVar6 + uVar14 * 4) = 0xffffffff;
                }
                if (*(int *)(iVar11 + uVar14 * 0x4c + 0x14) != -1) {
                  iVar20 = uVar14 * 0x4c + iVar11;
                  nbd_disconnect(iVar20);
                  *(undefined4 *)(iVar20 + 0x14) = 0xffffffff;
                }
LAB_00015b28:
                puts(DAT_000160ec);
                FUN_000149e4(uVar14,1);
                goto LAB_0001579c;
              }
              if (cVar2 == -8) {
                if (*(int *)(iVar11 + 0x130) < (int)uVar14) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_000161ec,DAT_00016288,DAT_000161e8,uVar14);
                }
                else {
                  memset(&local_174,0,DAT_000160fc);
                  local_174 = *(uint *)(iVar13 + 0x3e);
                  snprintf((char *)&uStack_168,0x100,DAT_0001614c,iVar13 + 0x42);
                  local_170 = uVar14;
                  uVar15 = snprintf(acStack_68,0x3f,DAT_0001614c,DAT_00016180 + uVar14 * 0x40);
                  if (uVar15 < 0x3f) {
                    local_16c = 1;
                    iVar20 = setRedirectedMediaInfo(4,&local_174);
                    if (iVar20 == 0) {
                      *(undefined4 *)(iVar11 + uVar14 * 0x4c) = 3;
                      goto LAB_0001579c;
                    }
                    IDBG_LINUXAPP_DbgOut(0x84,DAT_00016260,DAT_00016288,DAT_0001625c,uVar14);
                  }
                  else {
                    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016258,DAT_00016288,DAT_00016254);
                  }
                }
                IDBG_LINUXAPP_DbgOut(0x82,DAT_000161f4,DAT_00016288,DAT_000161f0,uVar14);
                goto LAB_00015b28;
              }
              iVar21 = *(int *)(iVar22 + 0x154);
              if (*(int *)(iVar22 + 0x53c) == 1) goto LAB_00015a98;
              if (iVar21 == 1) {
                switch(*(undefined4 *)(iVar22 + 0x144)) {
                case 0:
                case 1:
                  iVar20 = FUN_000138c0(0,uVar14);
                  break;
                case 2:
                  iVar20 = FUN_000138c0(2,uVar14);
                  break;
                case 3:
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_000160c8,DAT_00016190,DAT_000160c4);
                  iVar20 = FUN_000138c0(3,uVar14);
                  if (iVar20 == 0) goto LAB_000158d8;
                  goto LAB_000158c4;
                default:
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016278,DAT_00016288,DAT_00016274);
                  goto LAB_000158d8;
                }
                if ((iVar20 != 0) || (iVar20 = FUN_00013838(uVar14), iVar20 != 0)) {
LAB_000158c4:
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016138,DAT_00016190,DAT_000160c0);
                }
              }
LAB_000158d8:
              FUN_00012e68(uVar14);
              goto LAB_0001579c;
            }
            IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000160dc,DAT_00016190,DAT_000160d8);
            iVar21 = *(int *)(iVar22 + 0x154);
            *(undefined4 *)(iVar22 + 0x53c) = 1;
LAB_00015a98:
            if (iVar21 != 1) goto LAB_0001579c;
            switch(*(undefined4 *)(iVar11 + iVar20 + 0x144)) {
            case 0:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_000160e4,DAT_00016190,DAT_000160e0);
            case 2:
              iVar20 = FUN_000138c0(0,uVar14);
              break;
            case 1:
              iVar20 = FUN_000138c0(1,uVar14);
              break;
            case 3:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00016130,DAT_00016190,DAT_0001612c);
              iVar20 = FUN_000138c0(3,uVar14);
              if (iVar20 == 0) goto LAB_0001579c;
              goto LAB_00015aec;
            default:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_0001628c,DAT_00016288,DAT_00016284);
              goto LAB_0001579c;
            }
            if ((iVar20 != 0) || (iVar20 = FUN_00013838(uVar14), iVar20 != 0)) {
LAB_00015aec:
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00016138,DAT_00016190,0x3fc);
            }
          }
LAB_0001579c:
          uVar14 = uVar14 + 1 & 0xff;
        } while ((int)uVar14 < *(int *)(iVar11 + 0x130));
      }
      uVar14 = local_2f4 + 0x1f;
      if (-1 < (int)local_2f4) {
        uVar14 = local_2f4;
      }
      uVar15 = local_2f4 & 0x1f;
      if (-1 < (int)-local_2f4) {
        uVar15 = -(-local_2f4 & 0x1f);
      }
      if ((local_278[(int)uVar14 >> 5] & 1 << (uVar15 & 0xff)) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000160f4,DAT_00016190,DAT_000160f0);
        iVar20 = sigwrap_read(local_2f4,&local_2f6,2);
        if (iVar20 != 2) {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_00016104,DAT_00016190,DAT_00016118);
          goto LAB_000151b4;
        }
        uVar14 = (uint)local_2f6;
        uVar9 = DAT_000161cc;
        uVar19 = DAT_000161c8;
        if (*(int *)(iVar11 + 0x130) <= (int)uVar14) goto LAB_000168e8;
        iVar20 = iVar11 + uVar14 * 4;
        *(undefined4 *)(iVar20 + 0x20c) = 0;
        if (*(int *)(iVar20 + 0x1fc) == 0) goto LAB_000151b4;
        uVar14 = uVar14 & 0xff;
        iVar20 = iVar11 + uVar14 * 4;
        if (*(int *)(iVar20 + 0x154) != 1) goto LAB_00015ea4;
        switch(*(undefined4 *)(iVar20 + 0x144)) {
        case 0:
        case 2:
LAB_00016304:
          iVar20 = FUN_000138c0(1,uVar14);
          if (iVar20 != 0) {
LAB_00016314:
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00016138,DAT_00016190,DAT_00016134);
          }
          break;
        case 1:
          iVar20 = FUN_00013b20(uVar14);
          if (iVar20 == 0) goto LAB_00016304;
          iVar20 = FUN_000138c0(3,uVar14);
          if (iVar20 != 0) goto LAB_00016314;
          goto LAB_00015f18;
        case 3:
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00016194,DAT_00016190,DAT_0001618c);
          break;
        default:
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00016120,DAT_00016190,DAT_0001611c);
        }
LAB_00015ea4:
        iVar20 = *(int *)(iVar6 + (uint)local_2f6 * 4 + 0x20);
        if (iVar20 != -1) {
          uVar14 = local_2f6 & 0xff;
          if ((int)uVar14 < *(int *)(iVar11 + 0x130)) {
            pvVar10 = memcpy(*(void **)(DAT_000160bc + uVar14 * 4),
                             *(void **)(DAT_000160bc + uVar14 * 4 + 0x10),0x3e);
            *(undefined1 *)((int)pvVar10 + 0x35) = 0;
            *(undefined1 *)((int)pvVar10 + 0x36) = 0;
            *(undefined1 *)((int)pvVar10 + 0x37) = 0;
            *(undefined1 *)((int)pvVar10 + 0x38) = 0;
            *(undefined1 *)((int)pvVar10 + 0x39) = 0;
            *(undefined1 *)((int)pvVar10 + 0x3a) = 0;
            *(undefined1 *)((int)pvVar10 + 0x3b) = 0;
            *(undefined1 *)((int)pvVar10 + 0x3c) = 0;
            iVar20 = FUN_00013c74(iVar20,uVar14);
            if (iVar20 == 0) goto LAB_00015974;
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000161b8,DAT_00016288,DAT_000161b4);
          }
LAB_00015f18:
          FUN_000149e4((undefined1)local_2f6,1);
          goto LAB_000151b4;
        }
      }
LAB_00015974:
      if ((*(int *)(DAT_00016064 + 0x1e4) == 1 && bVar25) && ((uVar17 & local_278[iVar7]) != 0)) {
        iVar20 = sigwrap_read(local_320,&local_174,5);
        if (iVar20 != 5) {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_00016104,DAT_00016190,DAT_00016100);
          goto LAB_000151b4;
        }
        uVar14 = Get_index_to_racsessionid
                           (DAT_00016164,*(undefined4 *)(iVar11 + 0x130),
                            local_170 << 0x18 | local_174 >> 8);
        FUN_00013960(*(undefined4 *)(iVar6 + uVar14 * 4 + 0x20),uVar14 & 0xff,0xf6);
        sleep(3);
        FUN_000149e4(uVar14 & 0xff,1);
      }
      if ((*(int *)(DAT_00016064 + 0x1e8) == 1 && bVar24) && ((uVar12 & local_278[iVar1]) != 0)) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000160cc);
        iVar20 = sigwrap_read(local_31c,&local_2f7,1);
        if (iVar20 == 1) {
          iVar20 = GetVMediaCfg(&local_174,*(undefined4 *)(DAT_000161d0 + 0x68),
                                *(undefined4 *)(DAT_000161d0 + 0x74),
                                *(undefined4 *)(DAT_000161d0 + 0x180));
          if ((iVar20 == 0) && (local_16c != 0)) {
            bVar5 = true;
            if (bVar3) {
              uVar17 = 0;
              while( true ) {
                uVar12 = uVar17 & 0xff;
                if (*(int *)(iVar11 + 0x130) <= (int)uVar12) break;
                iVar7 = *(int *)(iVar6 + uVar12 * 4 + 0x20);
                uVar17 = uVar17 + 1;
                if (iVar7 != -1) {
                  shutdown(iVar7,2);
                  sigwrap_close(iVar7);
                }
                FUN_000149e4(uVar12,1);
              }
              if (*(int *)(iVar6 + 0x40) != -1) {
                ShutDownServer();
              }
              if (*(int *)(iVar6 + 0x44) != -1) {
                ShutDownServer();
              }
              iVar11 = DAT_000161d0;
              iVar6 = GetVMediaCfg(&local_174,*(undefined4 *)(DAT_000161d0 + 0x68),
                                   *(undefined4 *)(DAT_000161d0 + 0x74),
                                   *(undefined4 *)(DAT_000161d0 + 0x180));
              if (iVar6 == 0) {
                local_16c = iVar6;
                iVar11 = SetVMediaCfg(&local_174,*(undefined4 *)(iVar11 + 0x68),
                                      *(undefined4 *)(iVar11 + 0x74),*(undefined4 *)(iVar11 + 0x180)
                                     );
                if (iVar11 != 0) {
                  IDBG_LINUXAPP_DbgOut(0x82,DAT_00016268,DAT_00016288,DAT_00016264);
                }
              }
              else {
                IDBG_LINUXAPP_DbgOut(0x82,DAT_00016270,DAT_00016288,DAT_0001626c);
              }
              puts(DAT_000161c4);
              if (*(int *)(DAT_000161d0 + 0x1e8) == 1) {
LAB_000168c4:
                sigwrap_close(local_31c);
              }
LAB_000163a8:
              if (*(int *)(DAT_000161d0 + 0x1e4) == 1 && bVar25) {
                sigwrap_close(local_320);
              }
              sigwrap_close(local_2f4);
              sigwrap_close(local_2f0);
              return 0;
            }
          }
          else {
            bVar5 = false;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x84,DAT_000160d4,DAT_00016190,DAT_000160d0);
        }
      }
      goto LAB_000151b4;
    }
LAB_000168e8:
    IDBG_LINUXAPP_DbgOut(0x82,uVar9,DAT_00016288,uVar19);
    if (*(int *)(DAT_000161d0 + 0x1e8) == 1 && bVar24) {
      sigwrap_close(local_31c);
    }
    if (*(int *)(DAT_000161d0 + 0x1e4) == 1 && bVar25) {
      sigwrap_close(local_320);
    }
    sigwrap_close(local_2f4);
    sigwrap_close(local_2f0);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000161c0,DAT_00016288,DAT_000161bc);
    if (*(int *)(DAT_000161d0 + 0x1e8) == 1 && bVar24) {
      sigwrap_close(local_31c);
    }
    if (*(int *)(DAT_000161d0 + 0x1e4) == 1 && bVar25) {
      sigwrap_close(local_320);
      return 1;
    }
  }
  return 1;
}

