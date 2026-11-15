
void FUN_00010488(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined1 local_2e;
  byte local_2d;
  int local_2c;
  
  iVar2 = __gnu_mcount_nc();
  local_2d = 0;
  iVar4 = 0x3000000;
  local_2e = 5;
  local_2c = __stack_chk_guard;
  do {
    iVar3 = (**(code **)(iVar2 + 4))(&local_2e,1,&local_2d,1,0);
    if (iVar3 < 0) {
      printk("Error reading the SPI Status Register\n");
      break;
    }
    bVar1 = local_2d & 1;
    if ((local_2d & 1) == 0) goto LAB_00010508;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  printk("spi_generic: Waiting for Ready Failed %x\n",local_2d);
  bVar1 = 1;
LAB_00010508:
  if (local_2c == __stack_chk_guard) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(bVar1);
}

