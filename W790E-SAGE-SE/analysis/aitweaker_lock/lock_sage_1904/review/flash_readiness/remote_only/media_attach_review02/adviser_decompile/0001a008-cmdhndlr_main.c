
void cmdhndlr_main(void)

{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  int *piVar4;
  int iVar6;
  uint uVar7;
  char *pcVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  ushort *puVar12;
  int iVar13;
  int iVar14;
  undefined4 local_134;
  undefined4 local_130;
  undefined4 local_12c;
  undefined4 local_128;
  ushort local_124 [3];
  short local_11e;
  int local_11c [3];
  int local_110 [10];
  sysinfo local_e8;
  uint local_a8 [33];
  int *piVar5;
  
  prctl(0xf,DAT_0001a350,0,0,0);
  uVar3 = DAT_0001a35c;
  puVar2 = DAT_0001a358;
  uVar11 = 0;
  local_12c = 0;
  local_128 = DAT_0001a354;
  do {
    sem_wait(DAT_0001a360);
LAB_0001a054:
    sm_get_session_list(local_11c,0);
    if (local_11c[0] != 0) {
      pcVar8 = local_e8._f + 4;
      do {
        pcVar8 = pcVar8 + 4;
        pcVar8[0] = '\0';
        pcVar8[1] = '\0';
        pcVar8[2] = '\0';
        pcVar8[3] = '\0';
      } while ((uint *)pcVar8 != local_a8 + 0x1f);
      if (0 < local_11c[0]) {
        piVar4 = local_110;
        do {
          piVar5 = piVar4 + 1;
          if (*(int *)(*piVar4 + 4) != 0) {
            uVar9 = *(uint *)(*piVar4 + 0x4c);
            if ((int)uVar11 < (int)uVar9) {
              uVar11 = uVar9;
            }
            uVar7 = uVar9 + 0x1f;
            if (-1 < (int)uVar9) {
              uVar7 = uVar9;
            }
            uVar10 = uVar9 & 0x1f;
            if (-1 < (int)-uVar9) {
              uVar10 = -(-uVar9 & 0x1f);
            }
            local_a8[(int)uVar7 >> 5] = local_a8[(int)uVar7 >> 5] | 1 << (uVar10 & 0xff);
          }
          piVar4 = piVar5;
        } while (local_110 + local_11c[0] != piVar5);
      }
      iVar14 = 0;
      local_130 = 0;
      local_134 = 5;
      iVar6 = sigwrap_select(uVar11 + 1,local_a8,0,0,&local_134);
      if ((0 < iVar6) && (0 < local_11c[0])) {
        iVar6 = local_11c[0];
        piVar4 = local_110;
        do {
          while( true ) {
            iVar13 = *piVar4;
            uVar7 = *(uint *)(iVar13 + 0x4c);
            uVar9 = uVar7 + 0x1f;
            if (-1 < (int)uVar7) {
              uVar9 = uVar7;
            }
            uVar10 = uVar7 & 0x1f;
            if (-1 < (int)-uVar7) {
              uVar10 = -(-uVar7 & 0x1f);
            }
            if ((local_a8[(int)uVar9 >> 5] & 1 << (uVar10 & 0xff)) == 0) break;
            iVar6 = recv_bytes(uVar7,local_124,8,iVar13);
            if (iVar6 == 0) {
              puVar12 = DAT_0001a358;
              while( true ) {
                if (((*puVar12 == uVar3) && (*(int *)(iVar13 + 4) != 0)) &&
                   (*(int *)(iVar13 + 8) != 0)) {
                  iVar6 = handle_soc_specific_video_cmd(iVar13,local_124);
                  if (iVar6 != 0) goto LAB_0001a288;
                  sm_set_last_recv_time(*(undefined4 *)(iVar13 + 0x14));
                  if (*(int *)(DAT_0001a364 + 0x2b) <= *(int *)(iVar13 + 0x3fc)) goto LAB_0001a228;
                  sm_reset_kvm_timer(*(undefined4 *)(iVar13 + 0x14));
                  iVar6 = local_11c[0];
                  goto LAB_0001a134;
                }
                if ((uint)*puVar12 == (uint)local_124[0]) {
                  sm_set_last_recv_time(*(undefined4 *)(iVar13 + 0x14));
                  uVar1 = *puVar12;
                  if ((uVar1 != 0x3c && (uVar1 != 0x39 && uVar1 != 0x22)) &&
                     ((uVar1 != 0xb || (local_11e != 1)))) {
                    sm_reset_kvm_timer(*(undefined4 *)(iVar13 + 0x14));
                  }
                  iVar6 = (**(code **)(puVar12 + 2))(iVar13,local_124);
                  if (iVar6 == 0) goto LAB_0001a228;
                  goto LAB_0001a288;
                }
                if (0xf0 < (int)puVar12 - (int)puVar2) break;
                puVar12 = puVar12 + 4;
              }
              IDBG_LINUXAPP_DbgOut(0x82,DAT_0001a374,DAT_0001a370,DAT_0001a36c);
            }
LAB_0001a288:
            acquire_mutex(*(undefined4 *)(*piVar4 + 0x28));
            iVar6 = *piVar4;
            if (*(int *)(iVar6 + 4) != 0) {
              *(undefined4 *)(iVar6 + 0xc) = 1;
              iVar6 = *piVar4;
              if ((*(int *)(DAT_0001a368 + 0x324) == 1) && (*(int *)(iVar6 + 0x438) == 0)) {
                iVar13 = sysinfo(&local_e8);
                iVar6 = *piVar4;
                if (iVar13 == 0) {
                  *(long *)(iVar6 + 0x438) = local_e8.uptime;
                  iVar6 = *piVar4;
                }
              }
            }
            release_mutex(*(undefined4 *)(iVar6 + 0x28));
            sm_clean_sessions();
LAB_0001a228:
            iVar14 = iVar14 + 1;
            iVar6 = local_11c[0];
            piVar4 = piVar4 + 1;
            if (local_11c[0] <= iVar14) goto LAB_0001a054;
          }
LAB_0001a134:
          iVar14 = iVar14 + 1;
          piVar4 = piVar4 + 1;
        } while (iVar14 < iVar6);
      }
      goto LAB_0001a054;
    }
    sigwrap_nanosleep(&local_12c);
  } while( true );
}

