
void WS05_528ec(void)

{
  longlong lVar1;
  wchar_t *pwVar2;
  undefined1 local_res8 [8];
  undefined8 local_res10 [3];
  byte local_438 [71];
  char local_3f1;
  char local_374;
  
  local_res10[0] = 0x401;
  local_438[0] = 0xb8;
  local_438[1] = 0x9f;
  local_438[2] = 0xb;
  local_438[3] = 0xbc;
  local_438[4] = 0xcf;
  local_438[5] = 0x97;
  local_438[6] = 0x17;
  local_438[7] = 0x4b;
  local_438[8] = 0x9a;
  local_438[9] = 0x9e;
  local_438[10] = 0xf5;
  local_438[0xb] = 0x74;
  local_438[0xc] = 0xe6;
  local_438[0xd] = 0x2c;
  local_438[0xe] = 0xbc;
  local_438[0xf] = 0xc4;
  local_438[0x10] = 0x50;
  local_438[0x11] = 0xfe;
  local_438[0x12] = 0xda;
  local_438[0x13] = 0xe5;
  local_438[0x14] = 0xcb;
  local_438[0x15] = 0x10;
  local_438[0x16] = 0xb5;
  local_438[0x17] = 0x41;
  local_438[0x18] = 0x9c;
  local_438[0x19] = 0xb5;
  local_438[0x1a] = 0x27;
  local_438[0x1b] = 0x4e;
  local_438[0x1c] = 0x1c;
  local_438[0x1d] = 0xf1;
  local_438[0x1e] = 0xa8;
  local_438[0x1f] = 0xd7;
  lVar1 = (**(code **)(DAT_000afc48 + 0x140))(&DAT_00093618,0,&DAT_000b0098);
  if (-1 < lVar1) {
    pwVar2 = u_ServerSetup_000a9e80;
    (**(code **)(DAT_000afbd8 + 0x48))
              (u_ServerSetup_000a9e80,&DAT_00093658,local_res8,local_res10,local_438 + 0x20);
    if ((local_3f1 != '\0') || (local_374 != '\0')) {
      FUN_00052718(pwVar2,local_438);
      FUN_00052718(pwVar2,local_438 + 0x10);
    }
  }
  return;
}

