
void BeforeBootWdt_notify_callback(void)

{
  if (DAT_00001217 != '\0') {
    FUN_00000708(DAT_000011f0,1);
  }
  if (DAT_0000121a != '\0') {
    FUN_0000084c();
  }
  return;
}

