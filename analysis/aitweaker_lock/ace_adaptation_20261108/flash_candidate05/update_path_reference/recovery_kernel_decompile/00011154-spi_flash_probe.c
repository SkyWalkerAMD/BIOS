
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void spi_flash_probe(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined1 *puVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined1 local_51;
  undefined4 local_50;
  undefined4 uStack_4c;
  byte local_41;
  byte local_40;
  byte local_3f;
  char local_3d [9];
  int local_34;
  
  __gnu_mcount_nc();
  local_34 = __stack_chk_guard;
  hw_hal = (undefined4 *)kmem_cache_alloc_trace(_DAT_00013098,0xdc0,0x28);
  uVar8 = DAT_00011514;
  if (hw_hal == (undefined4 *)0x0) {
    printk("[%s] request kernel memory failed\n",DAT_00011520);
    uVar6 = 0xfffffff4;
  }
  else {
    *hw_hal = DAT_00011514;
    iVar3 = FUN_00010548(uVar8,0);
    puVar1 = hw_hal;
    if (iVar3 == 1) {
      printk("[SPI] SPI chip write enable timeout\n");
      uVar6 = 0xfffffc00;
    }
    else {
      local_51 = 0x9f;
      local_3d[4] = '\0';
      local_3d[5] = '\0';
      local_3d[6] = '\0';
      local_3d[7] = '\0';
      local_3d[0] = '\0';
      local_3d[1] = '\0';
      local_3d[2] = '\0';
      local_3d[3] = '\0';
      local_3d[8] = 0;
      ast_host_spi_flash_transfer(&local_51,1,&local_41,3);
      uVar7 = (uint)local_3f << 0x10 | (uint)local_40 << 8 | (uint)local_41;
      printk("[SPI]CE%d JEDEC ID = 0x%08X\n",ce_index,uVar7);
      sprintf(local_3d,"%08X",uVar7);
      printk("[SPI]%s read_id buf=0x%s id=%d\n",DAT_00011518,local_3d,uVar7);
      iVar3 = filp_open("/var/rom_id.tmp",0x241,0);
      if (iVar3 == 0) {
        printk("[SPI]%s filp_open failed\n",DAT_00011518);
      }
      else {
        uVar6 = *(undefined4 *)(((uint)&stack0xffffff8c & 0xffffe000) + 8);
        *(undefined4 *)(((uint)&stack0xffffff8c & 0xffffe000) + 8) = 0;
        DataSynchronizationBarrier(7);
        InstructionSynchronizationBarrier(0xf);
        local_50 = 0;
        uStack_4c = 0;
        iVar4 = kernel_write(iVar3,local_3d,9,&local_50);
        if (iVar4 < 0) {
          printk("[SPI]%s kernel_write failed\n",DAT_00011518);
        }
        *(undefined4 *)(((uint)&stack0xffffff8c & 0xffffe000) + 8) = uVar6;
        DataSynchronizationBarrier(7);
        InstructionSynchronizationBarrier(0xf);
      }
      filp_close(iVar3,0);
      if (uVar7 == DAT_00012228) {
        iVar3 = 0;
LAB_00011340:
        puVar5 = (undefined1 *)kmem_cache_alloc_trace(_DAT_000130a8,0xdc0,0x2d8);
        iVar4 = DAT_0001151c;
        if (puVar5 != (undefined1 *)0x0) {
          *(char **)(puVar5 + 0x40) = "Host SPI Flash";
          g_spi_info = iVar3 * 0x14 + iVar4;
          *(code **)(puVar5 + 0x60) = host_spi_flash_erase;
          *(code **)(puVar5 + 0x6c) = host_spi_flash_read;
          *(code **)(puVar5 + 0x70) = host_spi_flash_write;
          iVar3 = *(int *)(g_spi_info + 8);
          iVar4 = *(int *)(g_spi_info + 0xc);
          *(undefined4 *)(puVar5 + 4) = 0xc00;
          *(int *)(puVar5 + 0x18) = iVar3;
          _LANCHOR2 = uVar7;
          *puVar5 = 3;
          *(undefined4 *)(puVar5 + 0x14) = 0;
          *(undefined4 *)(puVar5 + 0x1c) = 1;
          *(int *)(puVar5 + 0x10) = iVar4 * iVar3;
        }
      }
      else {
        iVar4 = 0x12224;
        iVar3 = 1;
        do {
          if (*(uint *)(iVar4 + 0x18) == uVar7) goto LAB_00011340;
          iVar3 = iVar3 + 1;
          iVar4 = iVar4 + 0x14;
        } while (iVar3 != 0x16);
        printk("[%s] not support id 0x%06X\n",DAT_00011524,uVar7);
        puVar5 = (undefined1 *)0x0;
      }
      puVar2 = hw_hal;
      puVar1[1] = puVar5;
      if (puVar2[1] == 0) {
        printk("[SPI] Can\'t match SPI chip\n");
        kfree(hw_hal);
        uVar6 = 0xffffffed;
        hw_hal = (undefined4 *)0x0;
      }
      else {
        *(undefined1 **)(puVar2[1] + 0xf8) = &__this_module;
        uVar6 = 0;
        *(undefined4 *)(puVar2[1] + 0xf4) = uVar8;
        iVar3 = puVar2[1];
        puVar2[2] = "Host SPI Flash";
        puVar2[6] = 0;
        puVar2[7] = 0;
        uVar8 = *(undefined4 *)(iVar3 + 0x10);
        uVar9 = *(undefined4 *)(iVar3 + 0x14);
        puVar2[8] = 0;
        puVar2[4] = uVar8;
        puVar2[5] = uVar9;
        mtd_device_parse_register(iVar3,0,0,puVar2 + 2);
        if (hw_hal[5] == 0 && (uint)hw_hal[4] < 0x1000001) {
          uVar6 = 0;
        }
        else {
          DAT_000126c8 = 1;
          enter_4byte_addr_mode(DAT_00011514);
        }
      }
    }
  }
  if (local_34 != __stack_chk_guard) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(uVar6);
  }
  return;
}

