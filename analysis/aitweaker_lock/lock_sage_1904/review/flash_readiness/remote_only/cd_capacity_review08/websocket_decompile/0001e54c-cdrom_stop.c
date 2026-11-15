
undefined4 cdrom_stop(uint param_1)

{
  int iVar1;
  char *__s;
  
  iVar1 = pthread_cancel(*(pthread_t *)(DAT_0001e654 + param_1 * 4));
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e664,DAT_0001e660,0x278,param_1);
  }
  *(undefined4 *)(DAT_0001e658 + param_1 * 4) = 0;
  __s = calloc(0x400,1);
  snprintf(__s,0x400,DAT_0001e65c,param_1);
  iVar1 = safe_system(__s);
  free(__s);
  if (iVar1 != 0) {
    iVar1 = open_usb_gadget_cd_fd(DAT_0001e668);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e670,DAT_0001e660,DAT_0001e66c);
    }
    else {
      iVar1 = vmedia_cd_send_disk_eject_event(param_1 & 0xff);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e678,DAT_0001e660,DAT_0001e674,param_1);
      }
      close_usb_gadget_cd_fd();
    }
  }
  if (3 < (int)param_1) {
    return 0;
  }
  FUN_0001dd40(param_1);
  return 0;
}

