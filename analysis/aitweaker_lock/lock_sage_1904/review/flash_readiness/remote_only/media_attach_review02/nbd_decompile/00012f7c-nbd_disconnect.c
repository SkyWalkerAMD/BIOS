
void nbd_disconnect(undefined4 *param_1)

{
  if ((*DAT_00013060 & 1) != 0) {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013070,DAT_00013068,DAT_0001306c,param_1[5],*param_1);
  }
  if (param_1[4] != -1) {
    posix_fadvise64(param_1[4],0,0,4);
    ioctl(param_1[4],DAT_00013064);
  }
  FUN_00011ca0(param_1);
  return;
}

