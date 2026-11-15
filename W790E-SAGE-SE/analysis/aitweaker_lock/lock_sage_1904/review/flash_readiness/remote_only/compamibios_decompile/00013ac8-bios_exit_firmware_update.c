
undefined4 bios_exit_firmware_update(void)

{
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013b4c,DAT_00013b48,DAT_00013b50,DAT_00013b44);
  ActiveHostSPIDriver(1);
  send_compmngr_response();
  return 0;
}

