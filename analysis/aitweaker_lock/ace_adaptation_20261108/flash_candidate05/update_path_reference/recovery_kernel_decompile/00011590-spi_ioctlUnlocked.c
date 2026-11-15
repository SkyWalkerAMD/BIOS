
void spi_ioctlUnlocked(void)

{
  size_t __n;
  undefined4 uVar1;
  int iVar2;
  int *__s;
  char *pcVar3;
  uint extraout_r1;
  uint extraout_r2;
  uint uVar4;
  uint uVar5;
  undefined1 local_36;
  int local_35;
  undefined1 local_31;
  undefined4 local_30;
  int local_2c;
  
  __gnu_mcount_nc();
  uVar4 = *(uint *)(((uint)&stack0xffffffbc & 0xffffe000) + 8);
  if (extraout_r2 < 0xfffffffb && extraout_r2 + 5 <= uVar4) {
    uVar4 = 0;
  }
  local_31 = 0;
  local_35 = 0;
  local_2c = __stack_chk_guard;
  local_30 = 0;
  local_36 = 0;
  if (uVar4 == 0) {
    uVar5 = coproc_movefrom_Domain_Access_Control();
    uVar4 = uVar5 & 0xfffffff3 | 4;
    coproc_moveto_Domain_Access_Control(uVar4);
    InstructionSynchronizationBarrier(0xf);
    __n = arm_copy_from_user(&local_35,extraout_r2,5,uVar4);
    coproc_moveto_Domain_Access_Control(uVar5);
    InstructionSynchronizationBarrier(0xf);
    if (__n == 0) {
      if (local_35 == -0x3ffa9cff) {
        if (hw_hal == 0) {
          ce_index = extraout_r1 & 1;
          pcVar3 = "[SPI] CE%d selected\n";
        }
        else {
          pcVar3 = "[SPI]Device is already existed. Please remove CE%d device first\n";
        }
        printk(pcVar3,ce_index);
      }
      else if (local_35 == -0x3ffa9cfe) {
        if ((extraout_r1 & 1) == 0) {
          spi_flash_remove();
        }
        else if (hw_hal == 0) {
          ast_host_spi_flash_set_cs_range(0x2000000);
          hostspiflash_configure_clock(15000000);
          printk("[SPI] %s Set SPI clock 15MHz\n",DAT_000117e8);
          reset_flash();
          spi_flash_probe();
        }
        else {
          printk("[SPI]Device is already existed. Please remove it first\n");
        }
      }
      else if (local_35 == -0x3ffa9d00) {
        printk("[SPI]%s spi cmd\n",DAT_000117e8);
        local_36 = (undefined1)extraout_r1;
        ast_host_spi_flash_transfer(&local_36,1,&local_30,4);
        printk("0x%02X%02X%02X%02X\n",local_30 & 0xff,local_30._1_1_,local_30._2_1_);
      }
      uVar4 = *(uint *)(((uint)&stack0xffffffbc & 0xffffe000) + 8);
      if (extraout_r2 < 0xfffffffb && extraout_r2 + 5 <= uVar4) {
        uVar4 = 0;
      }
      if (uVar4 == 0) {
        iVar2 = arm_copy_to_user(extraout_r2,&local_35,5);
        uVar1 = 0;
        if (iVar2 == 0) goto LAB_00011758;
      }
      printk("[SPI] Copy to user failed\n");
      uVar1 = 0xffffffff;
      goto LAB_00011758;
    }
    __s = (int *)((int)&local_30 - __n);
  }
  else {
    __s = &local_35;
    __n = 5;
  }
  memset(__s,0,__n);
  printk("[SPI] Copy from user failed\n");
  uVar1 = 0xffffffff;
LAB_00011758:
  if (local_2c != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar1);
  }
  return;
}

