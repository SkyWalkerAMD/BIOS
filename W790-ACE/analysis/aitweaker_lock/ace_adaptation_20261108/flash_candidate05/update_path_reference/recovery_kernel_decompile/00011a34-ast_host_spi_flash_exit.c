
void ast_host_spi_flash_exit(void)

{
  printk("[SPI]%s\n",DAT_00011ab8);
  spi_flash_remove();
  if (DAT_000126cc != 0) {
    iounmap();
  }
  if (DAT_000126d0 != 0) {
    iounmap();
  }
  if (_LANCHOR1 != 0) {
    iounmap();
  }
  device_destroy(DAT_000126f0,0x6800000);
  class_destroy(DAT_000126f0);
  cdev_del(DAT_000126ec);
  unregister_chrdev_region(0x6800000,1);
  return;
}

