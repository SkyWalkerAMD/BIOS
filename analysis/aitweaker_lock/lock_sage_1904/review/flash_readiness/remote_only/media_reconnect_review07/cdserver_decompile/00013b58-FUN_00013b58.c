
void FUN_00013b58(uint param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  undefined2 local_3a;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  
  local_3a = (undefined2)param_1;
  local_38 = 0;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  iVar3 = snprintf((char *)&local_38,0x10,DAT_00013d8c,param_1);
  iVar2 = DAT_00013d90;
  if (iVar3 < 0x10) {
    uVar9 = 0;
    prctl(0xf,&local_38,0,0,0);
    if ((int)param_1 < *(int *)(iVar2 + 0x10)) {
      uVar7 = param_1 & 0xff;
      puVar6 = (undefined4 *)(DAT_00013d98 + uVar7 * 9);
      iVar5 = param_1 * DAT_00013d94 + DAT_00013d9c;
      iVar3 = param_1 * 4;
LAB_00013be4:
      iVar8 = *(int *)(iVar2 + iVar3 + 0x94);
      uVar1 = DAT_00013da0;
joined_r0x00013bf0:
      DAT_00013da0 = uVar1;
      if (iVar8 == 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013db0,param_1,iVar2 + iVar3,uVar9);
                    /* WARNING: Subroutine does not return */
        pthread_exit((void *)0x0);
      }
      if (*(int *)(iVar2 + 0x10) <= (int)uVar7) goto LAB_00013d58;
      do {
        uVar9 = 1;
        SetAuthInfo(*puVar6,puVar6[1],*(undefined1 *)(puVar6 + 2),iVar5,1);
        *(char *)(iVar5 + 0x17) = (char)param_1;
        iVar8 = iVar5;
        while( true ) {
          iVar8 = ioctl(*(int *)(iVar2 + 0x90),DAT_00013da4,iVar8);
          if (iVar8 == 0) {
            iVar8 = sigwrap_write(*(undefined4 *)(DAT_00013dbc + 4),&local_3a,2);
            if (iVar8 != 2) {
              uVar9 = param_1;
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00013dc4,uVar1,DAT_00013dc0,param_1);
            }
            *(undefined4 *)(iVar2 + iVar3 + 0xa4) = 1;
          }
          else {
            piVar4 = __errno_location();
            if (*piVar4 != 4) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00013db8,param_1,iVar8);
              goto LAB_00013be4;
            }
            if (*(int *)(iVar2 + iVar3 + 0x94) == 0) {
              uVar9 = param_1;
              IDBG_LINUXAPP_DbgOut(0x84,DAT_00013dac,DAT_00013da0,DAT_00013da8,param_1);
              iVar8 = *(int *)(iVar2 + iVar3 + 0x94);
              uVar1 = DAT_00013da0;
              goto joined_r0x00013bf0;
            }
            uVar9 = param_1;
            IDBG_LINUXAPP_DbgOut(0x84,DAT_00013dd0,uVar1,DAT_00013dcc,param_1);
          }
          if (*(int *)(iVar2 + iVar3 + 0x94) == 0) goto LAB_00013be4;
          if ((int)uVar7 < *(int *)(iVar2 + 0x10)) break;
LAB_00013d58:
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00013dc8,uVar1,0xee,uVar9);
          iVar8 = 0;
        }
      } while( true );
    }
  }
  IDBG_LINUXAPP_DbgOut(0x86,DAT_00013db4,param_1);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

