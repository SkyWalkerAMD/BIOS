
void P5Timer_from_link_map(void)

{
  longlong lVar1;
  ulonglong uVar2;
  char *pcVar3;
  
  if (((DAT_1400570dc == '\x01') && ((DAT_1400570e0 & 1) == 0)) && ((DAT_1400570d8 & 1) == 0)) {
    DAT_1400570e4 = DAT_1400570e4 + 1;
    if (DAT_1400570e4 < 0x15) {
      lVar1 = FUN_1400017d0();
      if (lVar1 < 0) {
        return;
      }
      DAT_1400570e0 = 1;
      DAT_1400570dc = 0;
      (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x58))(DAT_1400570b8,0,0);
      FUN_140003b90("P5_SETUP_AUTO_REFRESH\r\n");
      uVar2 = FUN_1400013d0();
      FUN_140003b90("P5_SETUP_REFRESH_STATUS=");
      FUN_140003c00(uVar2,0x10);
      pcVar3 = "\r\n";
    }
    else {
      DAT_1400570dc = 0;
      (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x58))(DAT_1400570b8,0,0);
      pcVar3 = "P5_NO_MATCHING_NATIVE_RESOURCE\r\n";
    }
    FUN_140003b90(pcVar3);
    return;
  }
  return;
}

