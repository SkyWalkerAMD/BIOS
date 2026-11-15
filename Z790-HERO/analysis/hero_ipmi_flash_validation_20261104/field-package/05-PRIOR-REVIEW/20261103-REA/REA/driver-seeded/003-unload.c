
longlong P5Unload_from_link_map(void)

{
  longlong lVar1;
  
  if (DAT_1400570d8 != '\0') {
    return -0x7ffffffffffffff1;
  }
  DAT_1400570dc = 0;
  if (DAT_1400570b8 != 0) {
    lVar1 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x70))();
    if (lVar1 < 0) {
      return lVar1;
    }
    DAT_1400570b8 = 0;
  }
  if (DAT_1400570c0 != 0) {
    lVar1 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x70))();
    if (lVar1 < 0) {
      return lVar1;
    }
    DAT_1400570c0 = 0;
  }
  if (DAT_1400570d0 != 0) {
    lVar1 = (**(code **)(*(longlong *)(DAT_140078d90 + 0x60) + 0x90))
                      (DAT_1400570d0,&DAT_140057000,&DAT_140057088);
    if (lVar1 < 0) {
      return lVar1;
    }
    DAT_1400570d0 = 0;
  }
  FUN_140001e50();
  return 0;
}

