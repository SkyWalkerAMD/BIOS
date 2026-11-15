
void FUN_00010548(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  undefined1 local_2f;
  undefined1 local_2e;
  byte local_2d;
  int local_2c;
  
  uVar6 = __gnu_mcount_nc();
  iVar1 = (int)uVar6;
  pcVar4 = *(code **)(iVar1 + 4);
  local_2c = __stack_chk_guard;
  if ((int)((ulonglong)uVar6 >> 0x20) == 0) {
    local_2f = 4;
    (*pcVar4)(&local_2f,1,0,0,0);
    pcVar4 = *(code **)(iVar1 + 4);
  }
  local_2f = 6;
  (*pcVar4)(&local_2f,1,0,0,0);
  iVar5 = 0x10;
  local_2d = 0;
  local_2e = 5;
  do {
    iVar2 = (**(code **)(iVar1 + 4))(&local_2e,1,&local_2d,1,0);
    if (iVar2 < 0) {
      printk("Error reading the SPI Status Register\n");
      break;
    }
    if ((local_2d & 2) != 0) {
      uVar3 = 0;
      goto LAB_0001061c;
    }
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  printk("ERROR: Write is not Enabled in the SPI Part...\n");
  printk("ERROR: write enable latch timeout\n");
  uVar3 = 1;
LAB_0001061c:
  if (local_2c == __stack_chk_guard) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(uVar3);
}

