
void WS05_15918(void)

{
  longlong lVar1;
  
  lVar1 = DAT_0001c348;
  while (lVar1 != 0) {
    if (*(longlong *)(lVar1 + 0x70) != 0) {
      WS05_6148();
    }
    lVar1 = *(longlong *)(lVar1 + 0x78);
    WS05_6148();
  }
  DAT_0001c348 = 0;
  return;
}

