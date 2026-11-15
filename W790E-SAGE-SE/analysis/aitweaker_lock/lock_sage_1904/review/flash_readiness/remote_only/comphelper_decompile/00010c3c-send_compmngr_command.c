
undefined4 send_compmngr_command(short *param_1,short *param_2,uint param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  char *pcVar8;
  uint uVar9;
  undefined4 uVar10;
  uint uVar11;
  uint *puVar12;
  uint local_b0 [35];
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f44,DAT_00010f48,0x18);
  uVar2 = mutex_create_recursive(DAT_00010f4c);
  iVar3 = mutex_lock_recursive(uVar2,10);
  if (iVar3 != 0) {
    mutex_destroy_recursive(uVar2);
    return 1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f50,DAT_00010f48,0x22);
  iVar4 = sigwrap_open(DAT_00010f54,1);
  iVar3 = DAT_00010f58;
  if (iVar4 == -1) {
    uVar10 = 0xfffffffe;
  }
  else {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f5c,DAT_00010f48,0x2b);
    iVar5 = sigwrap_write(iVar4,param_1,iVar3);
    if (iVar5 == iVar3) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f60,DAT_00010f48,0x36);
      uVar6 = sigwrap_open(DAT_00010f64,2);
      if (uVar6 == 0xffffffff) {
        sigwrap_close(iVar4);
        uVar10 = 0xffffffff;
      }
      else {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00010f68,DAT_00010f48,0x40);
        uVar1 = DAT_00010f6c;
        uVar10 = DAT_00010f48;
        uVar9 = uVar6 + 0x1f;
        if (-1 < (int)uVar6) {
          uVar9 = uVar6;
        }
        uVar11 = uVar6 & 0x1f;
        if (-1 < (int)-uVar6) {
          uVar11 = -(-uVar6 & 0x1f);
        }
        while( true ) {
          if (-1 < (int)param_3) {
            puVar12 = local_b0 + 1;
            do {
              puVar12 = puVar12 + 1;
              *puVar12 = 0;
            } while (local_b0 + 0x21 != puVar12);
            local_b0[1] = 0;
            local_b0[((int)uVar9 >> 5) + 2] = local_b0[((int)uVar9 >> 5) + 2] | 1 << (uVar11 & 0xff)
            ;
            local_b0[0] = param_3;
            iVar3 = sigwrap_select(uVar6 + 1,local_b0 + 2,0,0,local_b0);
            if (iVar3 == -1) {
              piVar7 = __errno_location();
              pcVar8 = strerror(*piVar7);
              printf(DAT_00010f78,pcVar8,param_3);
              sigwrap_close(iVar4);
              sigwrap_close(uVar6);
              uVar10 = 0xffffffff;
              goto LAB_00010cf0;
            }
            if (iVar3 == 0) {
              sigwrap_close(iVar4);
              sigwrap_close(uVar6);
              uVar10 = 0xfffffffd;
              goto LAB_00010cf0;
            }
          }
          iVar3 = sigwrap_read(uVar6,param_2,DAT_00010f58);
          if (iVar3 == iVar5) {
            uVar10 = 0;
            if (*param_1 != *param_2) {
              uVar10 = 0xffffffff;
            }
            sigwrap_close(iVar4);
            sigwrap_close(uVar6);
            goto LAB_00010cf0;
          }
          if (iVar3 != 0) break;
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar1,uVar10,0x69);
        }
        piVar7 = __errno_location();
        if (*piVar7 == 0xb || *piVar7 == 4) {
          puts(DAT_00010f74);
        }
        printf(DAT_00010f70,iVar3);
        sigwrap_close(iVar4);
        sigwrap_close(uVar6);
        uVar10 = 0xffffffff;
      }
    }
    else {
      sigwrap_close(iVar4);
      uVar10 = 0xffffffff;
    }
  }
LAB_00010cf0:
  mutex_unlock_recursive(uVar2);
  mutex_destroy_recursive(uVar2);
  return uVar10;
}

