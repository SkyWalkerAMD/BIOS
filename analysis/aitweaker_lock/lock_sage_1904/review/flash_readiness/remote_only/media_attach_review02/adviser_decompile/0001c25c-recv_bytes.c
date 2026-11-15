
undefined4 recv_bytes(uint param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  undefined4 local_f0;
  undefined4 local_ec;
  sysinfo local_e8;
  uint local_a8 [33];
  
  iVar6 = 0;
  uVar2 = param_1 + 0x1f;
  if (-1 < (int)param_1) {
    uVar2 = param_1;
  }
  uVar4 = param_1 & 0x1f;
  if (-1 < (int)-param_1) {
    uVar4 = -(-param_1 & 0x1f);
  }
  uVar4 = 1 << (uVar4 & 0xff);
  iVar7 = 0;
  iVar1 = (int)uVar2 >> 5;
  while( true ) {
    pcVar5 = local_e8._f + 4;
    do {
      pcVar5 = pcVar5 + 4;
      pcVar5[0] = '\0';
      pcVar5[1] = '\0';
      pcVar5[2] = '\0';
      pcVar5[3] = '\0';
    } while (local_a8 + 0x1f != (uint *)pcVar5);
    local_a8[iVar1] = local_a8[iVar1] | uVar4;
    local_f0 = 0x3c;
    local_ec = 0;
    iVar3 = sigwrap_select(param_1 + 1,local_a8,0,0,&local_f0);
    if (iVar3 < 1) break;
    if ((uVar4 & local_a8[iVar1]) != 0) {
      iVar6 = sigwrap_recv(param_1,param_2 + iVar7,param_3,0);
      if (iVar6 == 0) goto joined_r0x0001c3c4;
      if (iVar6 == -1) {
        if (param_4 == 0) {
          return 0xffffffff;
        }
        if (*(int *)(param_4 + 4) != 0) {
          acquire_mutex(*(undefined4 *)(param_4 + 0x28));
          iVar6 = DAT_0001c4ec;
          *(undefined4 *)(param_4 + 0xc) = 1;
          if (*(int *)(iVar6 + 0x324) == 1) {
            if ((*(int *)(param_4 + 0x438) == 0) && (iVar6 = sysinfo(&local_e8), iVar6 == 0)) {
              *(long *)(param_4 + 0x438) = local_e8.uptime;
            }
            usleep(100);
          }
          release_mutex(*(undefined4 *)(param_4 + 0x28));
          return 0xffffffff;
        }
        return 0xffffffff;
      }
    }
    param_3 = param_3 - iVar6;
    iVar7 = iVar7 + iVar6;
    if (param_3 == 0) {
      return 0;
    }
  }
  if (iVar3 != 0) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_0001c4f8,DAT_0001c4f0,0x99);
    if (param_4 == 0) {
      return 0xffffffff;
    }
    if (*(int *)(param_4 + 4) == 0) {
      return 0xffffffff;
    }
    acquire_mutex(*(undefined4 *)(param_4 + 0x28));
    iVar6 = DAT_0001c4ec;
    *(undefined4 *)(param_4 + 0xc) = 1;
    if (((*(int *)(iVar6 + 0x324) == 1) && (*(int *)(param_4 + 0x438) == 0)) &&
       (iVar6 = sysinfo(&local_e8), iVar6 == 0)) {
      *(long *)(param_4 + 0x438) = local_e8.uptime;
    }
    goto LAB_0001c3f4;
  }
  IDBG_LINUXAPP_DbgOut(0x84,DAT_0001c4f4,DAT_0001c4f0,0x7a);
joined_r0x0001c3c4:
  if (param_4 == 0) {
    return 0xffffffff;
  }
  if (*(int *)(param_4 + 4) == 0) {
    return 0xffffffff;
  }
  acquire_mutex(*(undefined4 *)(param_4 + 0x28));
  iVar6 = DAT_0001c4ec;
  *(undefined4 *)(param_4 + 0xc) = 1;
  if (*(int *)(iVar6 + 0x324) == 1) {
    if ((*(int *)(param_4 + 0x438) == 0) && (iVar6 = sysinfo(&local_e8), iVar6 == 0)) {
      *(long *)(param_4 + 0x438) = local_e8.uptime;
    }
    usleep(100);
  }
LAB_0001c3f4:
  release_mutex(*(undefined4 *)(param_4 + 0x28));
  return 0xffffffff;
}

