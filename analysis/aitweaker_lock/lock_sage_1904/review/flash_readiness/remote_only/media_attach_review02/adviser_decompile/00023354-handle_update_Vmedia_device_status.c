
void handle_update_Vmedia_device_status(void)

{
  if (*(int *)(DAT_00023368 + 0x1e4) != 1) {
    return;
  }
  FUN_0002280c();
  return;
}

