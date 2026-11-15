
ulonglong FUN_00042b78(void)

{
  uint *puVar1;
  uint *puVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  
  uVar5 = 0;
  if ((DAT_000aff22 != '\0') && (DAT_000aff40 != 0)) {
    FUN_0001b1b0(DAT_000aff40,*DAT_000baaf8);
    DAT_000aff40 = 0;
    DAT_000aff22 = '\0';
  }
  puVar2 = DAT_000baaf0;
  if ((DAT_000babc0 == 0) || (DAT_000aff68 == 0)) {
    uVar5 = 0x8000000000000003;
  }
  else {
    lVar4 = DAT_000babc0;
    uVar6 = uVar5;
    puVar1 = DAT_000baaf0;
    if (*DAT_000baaf0 != 0) {
      do {
        uVar3 = (ulonglong)puVar1[1];
        if (*(longlong *)(uVar3 + lVar4) == 0xffff) {
          *(undefined8 *)(uVar3 + lVar4) = 0;
          lVar4 = DAT_000babc0;
        }
        uVar6 = uVar6 + 1;
        puVar1 = puVar1 + 1;
      } while (uVar6 < *puVar2);
    }
  }
  return uVar5;
}

