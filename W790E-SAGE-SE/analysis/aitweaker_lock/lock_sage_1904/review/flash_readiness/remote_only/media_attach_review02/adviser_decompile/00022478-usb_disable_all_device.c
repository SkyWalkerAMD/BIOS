
void usb_disable_all_device(void)

{
  int iVar1;
  
  iVar1 = IsCardInActiveFlashMode();
  if (iVar1 != 0) {
    return;
  }
  iVar1 = IsCardInFlashMode();
  if (iVar1 != 0) {
    return;
  }
  iVar1 = IsLmediaRmediaRunning();
  if (iVar1 != 0) {
    return;
  }
  iVar1 = IsVirtualMediaRunning();
  if (iVar1 != 0) {
    return;
  }
  iVar1 = IsPowerconsumptionmode();
  if (iVar1 == 0) {
    return;
  }
  do_usb_ioctl(DAT_000224c8,0);
  return;
}

