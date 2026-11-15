
ulonglong FUN_1400013d0(void)

{
  ulonglong uVar1;
  ulonglong uVar2;
  
  if (DAT_1400570d8 == '\0') {
    DAT_1400570d8 = 1;
    uVar1 = FUN_1400017d0();
    FUN_140003b90("P5_BIND_STATUS=");
    FUN_140003c00(uVar1,0x10);
    FUN_140003b90("\r\n");
    if (-1 < (longlong)uVar1) {
      uVar1 = FUN_140001e80();
      uVar2 = FUN_140001b70();
      FUN_140003b90("P5_PUBLISH_STATUS=");
      FUN_140003c00(uVar2,0x10);
      FUN_140003b90("\r\n");
      if ((longlong)uVar2 < 0) {
        uVar1 = uVar2;
      }
    }
    DAT_1400570d8 = '\0';
  }
  else {
    uVar1 = 0x8000000000000014;
  }
  return uVar1;
}

