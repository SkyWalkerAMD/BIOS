
undefined4 spi_flash_remove(void)

{
  __gnu_mcount_nc();
  if (hw_hal != 0) {
    if (*(int *)(hw_hal + 4) != 0) {
      mtd_device_unregister(*(int *)(hw_hal + 4));
      kfree(*(undefined4 *)(hw_hal + 4));
      *(undefined4 *)(hw_hal + 4) = 0;
    }
    kfree();
    hw_hal = 0;
  }
  return 0;
}

