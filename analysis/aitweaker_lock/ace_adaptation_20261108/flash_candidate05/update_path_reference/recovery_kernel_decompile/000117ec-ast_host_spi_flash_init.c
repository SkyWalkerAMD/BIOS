
int ast_host_spi_flash_init(void)

{
  int iVar1;
  
  __gnu_mcount_nc();
  printk("[SPI]%s ce_index = %d\n",DAT_00011a2c,ce_index);
  iVar1 = register_chrdev_region(0x6800000,1,"ast_host_spi_flash");
  if (iVar1 < -1) {
    printk(&_LC29,iVar1);
  }
  else {
    DAT_000126ec = cdev_alloc();
    if (DAT_000126ec == 0) {
      printk(&_LC30,"ast_host_spi_flash");
      iVar1 = -0xc;
    }
    else {
      cdev_init(DAT_000126ec,DAT_00011a30);
      iVar1 = DAT_000126ec;
      *(undefined1 **)(DAT_000126ec + 0x24) = &__this_module;
      iVar1 = cdev_add(iVar1,0x6800000,1);
      if (iVar1 < 0) {
        printk(&_LC31,"ast_host_spi_flash");
      }
      else {
        DAT_000126f0 = __class_create(&__this_module,"host_spi",&DAT_000126f0);
        if (DAT_000126f0 < 0xfffff001) {
          device_create(DAT_000126f0,0,0x6800000,0,"host_spi");
          _LANCHOR1 = (uint *)ioremap(0x1e630000,0x1000);
          if (_LANCHOR1 == (uint *)0x0) {
            printk("[SPI] Get flash virt failed\n");
          }
          else {
            host_spi_flash_lock._0_4_ = 0;
            host_spi_flash_lock._4_4_ = 1;
            host_spi_flash_lock._8_4_ = 0x126dc;
            host_spi_flash_lock._12_4_ = 0x126dc;
            DAT_000126cc = ioremap(0x30000000,0x10000);
            if (DAT_000126cc == 0) {
              printk("[SPI] Get flash virt failed\n");
            }
            else {
              DAT_000126d0 = ioremap(0x32000000,0x10000);
              if (DAT_000126d0 != 0) {
                DataSynchronizationBarrier(0xf);
                DataSynchronizationBarrier(0xe);
                *_LANCHOR1 = *_LANCHOR1 | 0x30000;
                ast_host_spi_flash_set_cs_range(0x2000000);
                hostspiflash_configure_clock(15000000);
                printk("[SPI] %s Set SPI clock 15MHz\n",DAT_00011a2c);
                reset_flash();
                spi_flash_probe();
                return 0;
              }
              printk("[SPI] Get flash virt failed\n");
              iounmap(DAT_000126cc);
            }
            iounmap(_LANCHOR1);
          }
          device_destroy(DAT_000126f0,0x6800000);
          class_destroy(DAT_000126f0);
          iVar1 = -0xc;
        }
        else {
          iVar1 = -0x13;
        }
      }
      cdev_del(DAT_000126ec);
    }
    unregister_chrdev_region(0x6800000,1);
  }
  return iVar1;
}

