
void FUN_0005761c(void)

{
  char cVar1;
  longlong lVar2;
  longlong local_res8;
  undefined1 *local_res10;
  undefined8 local_res18 [2];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_res8 = 0;
  local_res10 = (undefined1 *)0x0;
  lVar2 = (**(code **)(DAT_000afbc8 + 0x140))(&DAT_00093938,0,&local_res8);
  if (-1 < lVar2) {
    local_res18[0] = 0xc;
    local_18 = 0xec87d643;
    local_14 = 0x4bb5eba4;
    local_10 = 0x3e3fe5a1;
    local_c = 0xa90db236;
    lVar2 = (**(code **)(local_res8 + 0x20))
                      (u_SetupLedData_000aa7a0,&local_18,&local_res10,local_res18);
    if (-1 < lVar2) {
      cVar1 = local_res10[4];
      if (cVar1 == '\0') {
        local_res10[4] = 0;
      }
      else {
        if (cVar1 == '\x01') {
          *local_res10 = 0;
          *(undefined2 *)(local_res10 + 3) = 0x100;
          local_res10[5] = 1;
          return;
        }
        if (cVar1 == '\x02') {
          *local_res10 = 0;
          local_res10[4] = 2;
          return;
        }
        if (cVar1 != '\x03') {
          return;
        }
        *(undefined2 *)(local_res10 + 3) = 0x300;
        local_res10[5] = 3;
      }
      *local_res10 = 2;
    }
  }
  return;
}

