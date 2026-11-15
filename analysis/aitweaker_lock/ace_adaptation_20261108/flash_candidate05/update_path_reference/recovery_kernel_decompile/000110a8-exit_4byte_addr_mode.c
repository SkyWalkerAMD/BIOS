
void exit_4byte_addr_mode(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined1 local_25;
  int local_24;
  
  iVar1 = __gnu_mcount_nc();
  local_25 = 0xe9;
  local_24 = __stack_chk_guard;
  iVar2 = FUN_00010488();
  if (iVar2 == 0) {
    iVar2 = (**(code **)(iVar1 + 4))(&local_25,1,0,0,0);
    if (iVar2 < 0) {
      printk("Could not Exit from 4-byte address mode\n");
      uVar3 = 0xffffffff;
    }
    else {
      (**(code **)(iVar1 + 0x10))(0);
      uVar3 = 0;
    }
  }
  else {
    uVar3 = 0xffffffff;
  }
  if (local_24 == __stack_chk_guard) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar3);
}

