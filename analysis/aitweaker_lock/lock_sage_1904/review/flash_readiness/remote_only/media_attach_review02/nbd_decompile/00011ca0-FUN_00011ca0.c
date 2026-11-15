
void FUN_00011ca0(undefined1 *param_1)

{
  if ((*DAT_00011f60 & 1) != 0) {
    IDBG_LINUXAPP_Runtime_DbgOut
              (0x87,DAT_00011f70,DAT_00011f6c,0xec,*(undefined4 *)(param_1 + 0x14));
  }
  if (*(int *)(param_1 + 0x10) != -1) {
    ioctl(*(int *)(param_1 + 0x10),DAT_00011f64);
    posix_fadvise64(*(int *)(param_1 + 0x10),0,0,4);
    ioctl(*(int *)(param_1 + 0x10),DAT_00011f68);
    close(*(int *)(param_1 + 0x10));
    param_1[0x10] = 0xff;
    param_1[0x11] = 0xff;
    param_1[0x12] = 0xff;
    param_1[0x13] = 0xff;
  }
  if (*(int *)(param_1 + 8) != -1) {
    close(*(int *)(param_1 + 8));
    param_1[8] = 0xff;
    param_1[9] = 0xff;
    param_1[10] = 0xff;
    param_1[0xb] = 0xff;
  }
  if (*(int *)(param_1 + 4) != -1) {
    close(*(int *)(param_1 + 4));
    param_1[4] = 0xff;
    param_1[5] = 0xff;
    param_1[6] = 0xff;
    param_1[7] = 0xff;
  }
  if (*(int *)(param_1 + 0xc) != -1) {
    close(*(int *)(param_1 + 0xc));
    param_1[0xc] = 0xff;
    param_1[0xd] = 0xff;
    param_1[0xe] = 0xff;
    param_1[0xf] = 0xff;
  }
  if (*(int *)(param_1 + 0x14) != -1) {
    FUN_00011bf8();
    param_1[0x14] = 0xff;
    param_1[0x15] = 0xff;
    param_1[0x16] = 0xff;
    param_1[0x17] = 0xff;
  }
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[0x30] = 0;
  param_1[0x31] = 0;
  param_1[0x32] = 0;
  param_1[0x33] = 0;
  param_1[0x34] = 0;
  param_1[0x35] = 0;
  param_1[0x36] = 0;
  param_1[0x37] = 0;
  param_1[0x40] = 0;
  param_1[0x41] = 0;
  param_1[0x42] = 0;
  param_1[0x43] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  param_1[0x2a] = 0;
  param_1[0x2b] = 0;
  param_1[0x2c] = 0;
  param_1[0x2d] = 0;
  param_1[0x2e] = 0;
  param_1[0x2f] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  param_1[0x22] = 0;
  param_1[0x23] = 0;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  param_1[0x26] = 0;
  param_1[0x27] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0;
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x48] = 0;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  param_1[0x4b] = 0;
  return;
}

