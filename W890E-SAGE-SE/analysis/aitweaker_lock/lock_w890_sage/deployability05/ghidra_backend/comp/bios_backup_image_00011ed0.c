
undefined4 bios_backup_image(undefined2 *param_1)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  undefined2 auStack_100b0 [2];
  undefined4 uStack_100ac;
  undefined2 uStack_100a8;
  char local_a4 [64];
  char local_64 [64];
  uint local_24;
  
  iVar3 = DAT_0001203c;
  local_24 = **(uint **)(DAT_00012034 + 0x11ee8 + DAT_00012038);
  local_a4[0] = '\0';
  local_a4[1] = '\0';
  local_a4[2] = '\0';
  local_a4[3] = '\0';
  memset(local_a4 + 4,0,0x3c);
  local_64[0] = '\0';
  local_64[1] = '\0';
  local_64[2] = '\0';
  local_64[3] = '\0';
  memset(local_64 + 4,0,0x3c);
  memset(auStack_100b0,0,DAT_00012040);
  iVar3 = *(int *)(iVar3 + 0x11f64 + DAT_00012044);
  snprintf(local_a4,0x40,(char *)(DAT_00012048 + 0x11f7c),*(undefined4 *)(iVar3 + 0x15c));
  snprintf(local_64,0x40,(char *)(DAT_0001204c + 0x11fac),*(undefined4 *)(iVar3 + 0x15c));
  iVar3 = rename(local_a4,local_64);
  if (iVar3 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012050 + 0x11fd8);
    uStack_100ac = 0xff;
  }
  uStack_100a8 = 0;
  auStack_100b0[0] = *param_1;
  uVar1 = send_compmngr_response(auStack_100b0);
  uVar2 = local_24 ^ **(uint **)(DAT_00012054 + 0x1200c + DAT_00012038);
  if (uVar2 != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar1,uVar2,0);
  }
  return 0;
}

