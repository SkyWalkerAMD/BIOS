
void WebSocketProxy(void)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  ssize_t sVar5;
  int iVar6;
  pthread_t __th;
  undefined4 *puVar7;
  char *pcVar8;
  int *piVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint *puVar13;
  undefined4 uVar14;
  int iVar15;
  int iVar16;
  char *pcVar17;
  __fd_mask *p_Var18;
  uint uVar19;
  int iVar20;
  int *piVar21;
  int iVar22;
  bool bVar23;
  uint local_1f0;
  int local_1ec;
  time_t local_1c4;
  int local_1c0;
  uint local_1bc;
  int local_1b8;
  pthread_t local_1b4;
  timeval local_1b0;
  undefined1 auStack_1a8 [41];
  undefined1 local_17f;
  sysinfo local_168;
  fd_set local_128;
  fd_set local_a8;
  
  local_1c0 = 0;
  local_1bc = 0;
  local_1b4 = 0;
  iVar22 = DAT_00017a00 + 0x17058;
  local_1b8 = -1;
  prctl(0xf,DAT_00017a04 + 0x17068,0,0,0);
  piVar21 = *(int **)(iVar22 + DAT_00017a08);
  puVar13 = (uint *)*piVar21;
  uVar10 = puVar13[1];
  if ((int)uVar10 <= (int)*puVar13) {
    uVar10 = *puVar13;
  }
  local_1c4 = 0;
  iVar20 = 0;
  iVar15 = DAT_00017a0c + 0x170b4;
  iVar16 = DAT_00017a10 + 0x170c0;
  pcVar17 = local_168._f + 4;
  pcVar8 = pcVar17;
LAB_000170f0:
  do {
    do {
      pcVar8 = pcVar8 + 4;
      pcVar8[0] = '\0';
      pcVar8[1] = '\0';
      pcVar8[2] = '\0';
      pcVar8[3] = '\0';
      p_Var18 = local_128.fds_bits + 0x1f;
    } while (local_128.fds_bits + 0x1f != (__fd_mask *)pcVar8);
    do {
      p_Var18 = p_Var18 + 1;
      *p_Var18 = 0;
    } while (local_a8.fds_bits + 0x1f != p_Var18);
    local_1b0.tv_usec = 0;
    local_1b0.tv_sec = 2;
    uVar11 = *puVar13;
    uVar19 = uVar11 + 0x1f;
    if (-1 < (int)uVar11) {
      uVar19 = uVar11;
    }
    uVar12 = uVar11 & 0x1f;
    if (-1 < (int)-uVar11) {
      uVar12 = -(-uVar11 & 0x1f);
    }
    local_a8.fds_bits[(int)uVar19 >> 5] = local_a8.fds_bits[(int)uVar19 >> 5] | 1 << (uVar12 & 0xff)
    ;
    uVar11 = *puVar13;
    uVar19 = uVar11 + 0x1f;
    if (-1 < (int)uVar11) {
      uVar19 = uVar11;
    }
    uVar12 = uVar11 & 0x1f;
    if (-1 < (int)-uVar11) {
      uVar12 = -(-uVar11 & 0x1f);
    }
    local_128.fds_bits[(int)uVar19 >> 5] =
         local_128.fds_bits[(int)uVar19 >> 5] | 1 << (uVar12 & 0xff);
    uVar11 = puVar13[1];
    uVar19 = uVar11 + 0x1f;
    if (-1 < (int)uVar11) {
      uVar19 = uVar11;
    }
    uVar12 = uVar11 & 0x1f;
    if (-1 < (int)-uVar11) {
      uVar12 = -(-uVar11 & 0x1f);
    }
    local_128.fds_bits[(int)uVar19 >> 5] =
         local_128.fds_bits[(int)uVar19 >> 5] | 1 << (uVar12 & 0xff);
    uVar11 = puVar13[1];
    uVar19 = uVar11 + 0x1f;
    if (-1 < (int)uVar11) {
      uVar19 = uVar11;
    }
    uVar12 = uVar11 & 0x1f;
    if (-1 < (int)-uVar11) {
      uVar12 = -(-uVar11 & 0x1f);
    }
    local_a8.fds_bits[(int)uVar19 >> 5] = local_a8.fds_bits[(int)uVar19 >> 5] | 1 << (uVar12 & 0xff)
    ;
    iVar3 = select(uVar10 + 1,&local_128,(fd_set *)0x0,&local_a8,&local_1b0);
    if (iVar3 == -1) {
      piVar21 = __errno_location();
      pcVar8 = strerror(*piVar21);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a54 + 0x177b8,DAT_00017a50 + 0x177b4,DAT_00017a58,pcVar8);
LAB_000175e0:
      __th = pthread_self();
      pthread_detach(__th);
                    /* WARNING: Subroutine does not return */
      pthread_exit((void *)0x0);
    }
    puVar13 = (uint *)*piVar21;
    pcVar8 = pcVar17;
  } while (iVar3 == 0);
  uVar19 = puVar13[1];
  if (uVar19 != 0xffffffff) {
    uVar11 = uVar19 + 0x1f;
    if (-1 < (int)uVar19) {
      uVar11 = uVar19;
    }
    uVar12 = uVar19 & 0x1f;
    if (-1 < (int)-uVar19) {
      uVar12 = -(-uVar19 & 0x1f);
    }
    if ((local_128.fds_bits[(int)uVar11 >> 5] & 1 << (uVar12 & 0xff)) != 0) {
      uVar19 = 0;
      iVar3 = 0;
      iVar4 = 0;
      local_1f0 = 0;
      local_1ec = 0;
      while( true ) {
        while( true ) {
          while( true ) {
            uVar11 = ws_recv(puVar13,puVar13[9] + uVar19,DAT_00017a28);
            puVar13 = (uint *)*piVar21;
            if (0 < (int)uVar11) break;
            if ((SSL *)puVar13[3] == (SSL *)0x0) {
              piVar9 = __errno_location();
              if (*piVar9 != 0xb) {
                IDBG_LINUXAPP_DbgOut
                          (0x82,DAT_00017a3c + 0x1761c,DAT_00017a38 + 0x17614,DAT_00017a40,*piVar9);
                goto LAB_00017620;
              }
            }
            else {
              iVar6 = SSL_get_error((SSL *)puVar13[3],uVar11);
              if (iVar6 != 5 && iVar6 != 2) {
                iVar20 = SSL_get_error(*(SSL **)(*piVar21 + 0xc),uVar11);
                IDBG_LINUXAPP_DbgOut
                          (0x82,DAT_00017a60 + 0x17838,DAT_00017a5c + 0x17834,0x388,iVar20);
                goto LAB_00017620;
              }
              puVar13 = (uint *)*piVar21;
            }
          }
          bVar23 = CARRY4(uVar19,uVar11);
          uVar19 = uVar19 + uVar11;
          iVar3 = iVar3 + ((int)uVar11 >> 0x1f) + (uint)bVar23;
          if (puVar13[5] != 0) {
            iVar20 = decode_websocket_hybi
                               (puVar13[9] + local_1f0,local_1f0,uVar19 - local_1f0,
                                iVar3 - (local_1ec + (uint)(uVar19 < local_1f0)),puVar13[10] + iVar4
                                ,DAT_00017a28,&local_1c0,&local_1bc,&local_1b8);
          }
          if (local_1c0 == 8) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a30 + 0x175b8,DAT_00017a2c + 0x175b4,DAT_00017a34);
            iVar20 = DAT_00017a20;
            *(undefined4 *)(*piVar21 + 4) = 0xffffffff;
            cleanup_instance(**(undefined4 **)(iVar22 + iVar20),1);
            goto LAB_000175e0;
          }
          if (iVar20 < 0) {
            IDBG_LINUXAPP_DbgOut(0x82,iVar16,iVar15,DAT_00017a44);
            fflush((FILE *)**(undefined4 **)(iVar22 + DAT_00017a48));
          }
          iVar4 = iVar4 + iVar20;
          puVar13 = (uint *)*piVar21;
          if (local_1bc == 0) break;
          local_1f0 = uVar19 - local_1bc;
          local_1ec = iVar3 - (uint)(uVar19 < local_1bc);
        }
        uVar19 = puVar13[10];
        if ((*(int *)(uVar19 + 0x39) + 0x3d == iVar4) || (local_1b8 != 0)) break;
        uVar19 = 0;
        iVar3 = 0;
        local_1f0 = 0;
        local_1ec = 0;
      }
      cVar1 = *(char *)(uVar19 + 0x29);
      bVar2 = cVar1 + 0xeU;
      if (1 < (byte)(cVar1 + 0xeU)) {
        bVar2 = cVar1 + 9;
      }
      if (bVar2 < 2) {
        sendDataToServer(*puVar13,uVar19,iVar20);
        iVar3 = DAT_00017a70;
        if (*(char *)(uVar19 + 0x29) == -9) {
          pthread_cancel(local_1b4);
          pthread_join(local_1b4,(void **)0x0);
          if (*(int *)(iVar3 + 0x179d4) != -1) {
            cdrom_stop();
            *(undefined4 *)(iVar3 + 0x179d4) = 0xffffffff;
          }
          nbd_disconnect(*piVar21 + 0x34);
LAB_00017620:
          cleanup_instance(**(undefined4 **)(iVar22 + DAT_00017a20),1);
          goto LAB_000175e0;
        }
      }
      else {
        if (cVar1 == '%') {
          uVar11 = *(uint *)(uVar19 + 0x41);
          uVar12 = *(uint *)(uVar19 + 0x3d);
          uVar11 = (uVar11 ^ (uVar11 >> 0x10 | uVar11 << 0x10)) >> 8 & 0xffff00ff ^
                   (uVar11 >> 8 | uVar11 << 0x18);
          *(uint *)(uVar19 + 0x41) = uVar11;
          *(uint *)(uVar19 + 0x3d) =
               (uVar12 ^ (uVar12 >> 0x10 | uVar12 << 0x10)) >> 8 & 0xffff00ff ^
               (uVar12 >> 8 | uVar12 << 0x18);
          puVar13[0x13] = uVar11;
          puVar13[0x14] = 0;
          puVar13[0x15] = *(int *)(uVar19 + 0x3d) + 1;
          puVar13[0x16] = 0;
          *(undefined2 *)(puVar13 + 0x1e) = 1;
          iVar4 = nbd_init(puVar13 + 0xd);
          iVar3 = DAT_00017a64;
          if (iVar4 == -1) goto LAB_000175e0;
          *(undefined4 *)(*piVar21 + 0x34) = 1;
          iVar3 = pthread_create(&local_1b4,(pthread_attr_t *)0x0,
                                 *(__start_routine **)(iVar22 + iVar3),(void *)0x0);
          if (iVar3 != 0) {
            nbd_disconnect(*piVar21 + 0x34);
            sendCmdToCdserver(*(undefined4 *)*piVar21,0xf7,**(undefined4 **)(iVar22 + DAT_00017a18))
            ;
            goto LAB_000175e0;
          }
        }
        else if (cVar1 == -0x58) {
          puVar13[0x1f] = uVar19 + 0x3d;
          iVar4 = nbd_write_res(puVar13 + 0xd);
          iVar3 = DAT_00017a74;
          if (iVar4 == -1) {
            if (*(int *)((int)&DAT_00017a10 + DAT_00017a74) != -1) {
              cdrom_stop();
              *(undefined4 *)((int)&DAT_00017a10 + iVar3) = 0xffffffff;
            }
            nbd_disconnect(*piVar21 + 0x34);
            sendCmdToCdserver(*(undefined4 *)*piVar21,0xf7,**(undefined4 **)(iVar22 + DAT_00017a18))
            ;
          }
          else {
            *(undefined4 *)(*piVar21 + 0x34) = 1;
          }
        }
        iVar3 = sysinfo(&local_168);
        if (iVar3 == 0) {
          local_1c4 = local_168.uptime;
        }
      }
      puVar13 = (uint *)*piVar21;
    }
  }
  uVar11 = *puVar13;
  uVar19 = uVar11 + 0x1f;
  if (-1 < (int)uVar11) {
    uVar19 = uVar11;
  }
  uVar12 = uVar11 & 0x1f;
  if (-1 < (int)-uVar11) {
    uVar12 = -(-uVar11 & 0x1f);
  }
  if ((local_128.fds_bits[(int)uVar19 >> 5] & 1 << (uVar12 & 0xff)) != 0) {
    sVar5 = recv(uVar11,(void *)(puVar13[7] + 10),DAT_00017a24,0);
    if (sVar5 < 1) {
      piVar9 = __errno_location();
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017a68 + 0x17924,DAT_00017a6c + 0x17920,0x420,*piVar9);
      *(undefined4 *)*piVar21 = 0xffffffff;
      goto LAB_000175e0;
    }
    iVar4 = *piVar21;
    iVar3 = *(int *)(iVar4 + 0x1c);
    if (*(char *)(iVar3 + 0x33) == -0xf) {
      uVar11 = (uint)*(byte *)(iVar3 + 0x48);
      uVar14 = *(undefined4 *)(iVar4 + 0x14);
      uVar19 = uVar11;
      if (uVar11 != 1) {
        uVar19 = uVar11 - 0x1b;
      }
      if (uVar19 != 0 && (uVar11 != 1 && uVar11 - 0x1b != 1)) {
        sendDataToH5Viewer(iVar3,sVar5,uVar14);
        goto LAB_000175e0;
      }
      **(uint **)(iVar22 + DAT_00017a18) = (uint)*(byte *)(iVar3 + 0x21);
      sendDataToH5Viewer(iVar3,sVar5,uVar14);
      memset(auStack_1a8,0,0x3e);
      local_17f = 0x25;
      FUN_00015bc8();
    }
    else if (*(char *)(iVar3 + 0x33) == -0xd) {
      iVar3 = sysinfo(&local_168);
      if (iVar3 == 0) {
        difftime(local_168.uptime,local_1c4);
        iVar3 = FUN_0001fd10();
        puVar7 = (undefined4 *)*piVar21;
        if (iVar3 == 0) {
          sendCmdToCdserver(*puVar7,0xf3,**(undefined4 **)(iVar22 + DAT_00017a18));
          local_1c4 = 0;
        }
        else {
          sendDataToH5Viewer(puVar7[7],sVar5,puVar7[5]);
          local_1c4 = 0;
        }
      }
    }
    else {
      sendDataToH5Viewer(iVar3,sVar5,*(undefined4 *)(iVar4 + 0x14));
    }
  }
  iVar3 = DAT_00017a14;
  iVar4 = *(int *)(DAT_00017a14 + 0x17304);
  if (local_1c0 == 8) {
LAB_00017358:
    if ((iVar4 != -1) && (iVar3 = cdrom_eject_status(), iVar3 == 1)) {
      memset(auStack_1a8,0,0x3e);
      local_17f = 0xf7;
      FUN_00015bc8();
    }
    iVar3 = DAT_00017a1c;
    sendCmdToCdserver(*(undefined4 *)*piVar21,0xf7,**(undefined4 **)(iVar22 + DAT_00017a18));
    pthread_cancel(local_1b4);
    pthread_join(local_1b4,(void **)0x0);
    if (*(int *)(iVar3 + 0x173f0) != -1) {
      cdrom_stop();
      *(undefined4 *)(iVar3 + 0x173f0) = 0xffffffff;
    }
    nbd_disconnect(*piVar21 + 0x34);
    cleanup_instance(**(undefined4 **)(iVar22 + DAT_00017a20),1);
  }
  else if ((iVar4 != -1) && (iVar4 = cdrom_eject_status(), iVar4 == 1)) {
    iVar4 = *(int *)(iVar3 + 0x17304);
    goto LAB_00017358;
  }
  puVar13 = (uint *)*piVar21;
  uVar11 = puVar13[1];
  uVar19 = uVar11 + 0x1f;
  if (-1 < (int)uVar11) {
    uVar19 = uVar11;
  }
  uVar12 = uVar11 & 0x1f;
  if (-1 < (int)-uVar11) {
    uVar12 = -(-uVar11 & 0x1f);
  }
  if ((local_128.fds_bits[(int)uVar19 >> 5] & 1 << (uVar12 & 0xff)) == 0) {
    uVar11 = *puVar13;
    uVar19 = uVar11 + 0x1f;
    if (-1 < (int)uVar11) {
      uVar19 = uVar11;
    }
    uVar12 = uVar11 & 0x1f;
    if (-1 < (int)-uVar11) {
      uVar12 = -(-uVar11 & 0x1f);
    }
    if ((local_128.fds_bits[(int)uVar19 >> 5] & 1 << (uVar12 & 0xff)) == 0) goto LAB_000170f0;
  }
  NanoSleep(1);
  puVar13 = (uint *)*piVar21;
  goto LAB_000170f0;
}

