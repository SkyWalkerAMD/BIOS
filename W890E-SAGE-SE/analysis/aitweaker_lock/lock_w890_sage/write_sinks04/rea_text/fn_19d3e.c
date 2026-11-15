
void FUN_00019cf8(void)

{
  longlong lVar1;
  
  DAT_000bab20 = DAT_000babc0;
  DAT_000baae0 = (ulonglong)*(uint *)(DAT_000babc0 + 0x28) + DAT_000babc0;
  DAT_000baaf0 = (ulonglong)*(uint *)(DAT_000babc0 + 0x2c) + DAT_000babc0;
  DAT_000bab28 = (ulonglong)*(uint *)(DAT_000babc0 + 0x30) + DAT_000babc0;
  DAT_000baaf8 = (ulonglong)*(uint *)(DAT_000babc0 + 0x34) + DAT_000babc0;
  DAT_000baad8 = (ulonglong)*(uint *)(DAT_000babc0 + 0x38) + DAT_000babc0;
  DAT_000baac0 = (ulonglong)*(uint *)(DAT_000babc0 + 0x3c) + DAT_000babc0;
  DAT_000baad0 = DAT_000babc0 + (ulonglong)*(uint *)(DAT_000babc0 + 0x40);
  DAT_000baac8 = (ulonglong)*(uint *)(DAT_000baad0 + 4) + DAT_000baad0;
  lVar1 = (longlong)DAT_000babd8;
  DAT_000baae8 = DAT_000baad0;
  DAT_000bab00 = DAT_000baaf8;
  DAT_000bab10 = DAT_000baaf0;
  DAT_000bab18 = DAT_000baac8;
  if (DAT_000babd8 != (undefined8 *)0x0) {
    (**(code **)(DAT_000afbc8 + 0x48))();
    DAT_000babd8 = (undefined8 *)0x0;
  }
  DAT_000babd8 = FUN_00059b50(lVar1,0x50);
  *(undefined1 *)(DAT_000babd8 + 9) = 0;
  *(undefined1 *)((longlong)DAT_000babd8 + 0x49) = 0;
  DAT_000babd8[8] = 0;
  DAT_000babd8[7] = 0;
  return;
}

