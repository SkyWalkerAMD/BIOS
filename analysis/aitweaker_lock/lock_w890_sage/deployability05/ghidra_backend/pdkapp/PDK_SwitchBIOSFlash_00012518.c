
void PDK_SwitchBIOSFlash(char param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 local_48;
  char local_44 [40];
  int local_1c;
  
  uVar2 = 0;
  local_1c = **(int **)(DAT_00012654 + 0x1252c + DAT_00012658);
  local_44[0] = '\0';
  local_44[1] = '\0';
  local_44[2] = '\0';
  local_44[3] = '\0';
  memset(local_44 + 4,0,0x24);
  local_48 = DAT_00012660;
  snprintf(local_44,0x28,(char *)(DAT_0001265c + 0x1256c),0xf);
  iVar1 = sigwrap_open(local_44,2);
  if (-1 < iVar1) {
    write(iVar1,&local_48,3);
    sigwrap_close(iVar1);
    memset(local_44,0,0x28);
    local_48 = 0;
    snprintf(local_44,0x28,(char *)(DAT_00012670 + 0x1260c),0xf);
    iVar1 = sigwrap_open(local_44,2);
    if (-1 < iVar1) {
      local_48 = CONCAT31(local_48._1_3_,param_1 + '0');
      write(iVar1,&local_48,1);
      sigwrap_close(iVar1);
      goto LAB_000125a8;
    }
  }
  printf((char *)(DAT_00012668 + 0x125a4),DAT_00012664 + 0x125a0);
  uVar2 = 0xffffffff;
LAB_000125a8:
  if (local_1c != **(int **)(DAT_0001266c + 0x125b8 + DAT_00012658)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar2);
  }
  return;
}

