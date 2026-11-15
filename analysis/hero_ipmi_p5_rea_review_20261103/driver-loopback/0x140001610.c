
void FUN_140001610(void)

{
  longlong lVar1;
  
  if (((DAT_1400570e0 == '\0') && ((DAT_1400570dc & 1) == 0)) && ((DAT_1400570d8 & 1) == 0)) {
    DAT_1400570dc = 1;
    DAT_1400570e4 = 0;
    lVar1 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x58))(DAT_1400570b8,1,5000000);
    if (lVar1 < 0) {
      DAT_1400570dc = 0;
      FUN_140003b90("P5_TIMER_ARM_FAILED\r\n");
      return;
    }
  }
  return;
}

