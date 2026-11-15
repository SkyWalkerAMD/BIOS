
undefined4 bios_prepare_comp(undefined2 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  char *__name;
  int iVar4;
  sysinfo sStack_10098;
  undefined2 auStack_10058 [2];
  int iStack_10054;
  undefined2 uStack_10050;
  char local_4c [32];
  uint local_2c;
  
  iVar4 = DAT_00013718;
  local_2c = **(uint **)(DAT_0001370c + 0x13478 + DAT_00013710);
  *(undefined4 *)(DAT_00013714 + 0x134b8) = 0;
  iVar4 = iVar4 + 0x134d0;
  local_4c[0] = '\0';
  local_4c[1] = '\0';
  local_4c[2] = '\0';
  local_4c[3] = '\0';
  memset(local_4c + 4,0,0x1c);
  Getpdklib(0);
  memset(auStack_10058,0,DAT_0001371c);
  if (**(int **)(iVar4 + DAT_00013720) == *(int *)(param_1 + 5)) {
    uVar3 = *(uint *)(param_1 + 7);
    strcpy(local_4c,(char *)(DAT_0001372c + 0x13594));
    iVar2 = Check_FeatureList();
    if (iVar2 == 1) {
      iVar2 = ActiveHostSPIDriver(0);
      if (iVar2 == 0) {
        iVar2 = asus_find_bios_spi_device(*(undefined4 *)(iVar4 + DAT_0001373c));
        if (iVar2 == 0) {
          iVar2 = sysinfo(&sStack_10098);
          if (iVar2 != 0) {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_00013744 + 0x1364c,iVar2);
            goto LAB_000135e4;
          }
          if (uVar3 <= sStack_10098.freeram) {
            **(uint **)(iVar4 + DAT_0001374c) = (uint)((uVar3 & 0xffffff) != 0);
            **(uint **)(iVar4 + DAT_00013750) = uVar3;
            iVar2 = access(local_4c,0);
            if (iVar2 == 0) {
              unlink(local_4c);
            }
            __name = (char *)(DAT_00013754 + 0x136c0);
            iVar2 = access(__name,0);
            if (iVar2 == 0) {
              unlink(__name);
            }
            **(undefined4 **)(iVar4 + DAT_00013758) = 0;
            iStack_10054 = 0;
            **(undefined4 **)(iVar4 + DAT_0001375c) = 0;
            goto LAB_00013520;
          }
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013748 + 0x13670,uVar3);
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013740 + 0x13618);
        }
        iStack_10054 = 0xffffff;
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013738 + 0x135e4);
LAB_000135e4:
        iStack_10054 = 0xffffff;
      }
      goto LAB_00013520;
    }
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013734 + 0x135c0,DAT_00013730 + 0x13665);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013724 + 0x13514);
  }
  iStack_10054 = 6;
LAB_00013520:
  uStack_10050 = 0;
  if (iStack_10054 != 0) {
    Getpdklib(2);
    ActiveHostSPIDriver(1);
  }
  auStack_10058[0] = *param_1;
  uVar1 = send_compmngr_response(auStack_10058);
  uVar3 = local_2c ^ **(uint **)(DAT_00013728 + 0x13564 + DAT_00013710);
  if (uVar3 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar1,uVar3,0);
  }
  return 0;
}

