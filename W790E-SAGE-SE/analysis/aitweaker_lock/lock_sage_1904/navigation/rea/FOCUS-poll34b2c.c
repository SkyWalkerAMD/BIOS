
void FUN_00034b2c(void)

{
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_18 = 0xc7a047a8;
  local_14 = 0x48db82b1;
  local_10 = 0x277b6a8e;
  local_c = 0x1f567ccc;
  if ((DAT_000837d8 == (undefined8 *)0x0) &&
     ((**(code **)(DAT_00083308 + 0x140))(&local_18,0,&DAT_000837d8),
     DAT_000837d8 == (undefined8 *)0x0)) {
    return;
  }
  (*(code *)*DAT_000837d8)();
  return;
}

