
longlong FUN_000143ac(void)

{
  longlong lVar1;
  short in_R9W;
  char local_228 [16];
  undefined4 local_218;
  undefined4 uStack_214;
  undefined4 uStack_210;
  undefined4 uStack_20c;
  undefined8 local_208;
  longlong local_200;
  undefined1 local_1f8 [16];
  undefined4 local_1e8;
  undefined4 uStack_1e4;
  undefined4 uStack_1e0;
  undefined4 uStack_1dc;
  undefined1 local_1d8 [375];
  char local_61;
  
  local_200 = 0;
  local_218 = 0xec87d643;
  uStack_214 = 0x4bb5eba4;
  uStack_210 = 0x3e3fe5a1;
  uStack_20c = 0xa90db236;
  local_208 = 0x1cb;
  if (DAT_00048180 != '\0') {
    if ((DAT_00048190 == 0) || (*(longlong *)(DAT_00048190 + 8) == 0x1000)) {
      return -0x7ffffffffffffffd;
    }
    if (*(longlong *)(DAT_00048190 + 8) != 1) {
      return 0;
    }
    DAT_00048180 = '\0';
  }
  if ((DAT_00048268 == 0) &&
     (lVar1 = (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c5e8,0,&DAT_00048268), lVar1 < 0)) {
    return lVar1;
  }
  lVar1 = (**(code **)(DAT_000483e8 + 0x48))
                    (u_Setup_00041658,&local_218,local_1f8,&local_208,local_1d8);
  if (lVar1 < 0) {
    return lVar1;
  }
  local_1e8 = local_218;
  uStack_1e4 = uStack_214;
  uStack_1e0 = uStack_210;
  uStack_1dc = uStack_20c;
  lVar1 = (**(code **)(DAT_00048268 + 0x20))(u_Setup_00041658,&local_1e8,&DAT_00048278,&local_208);
  if (-1 < lVar1) {
    lVar1 = (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c3d8,0,&local_200);
    if (-1 < lVar1) {
      if (in_R9W == 0x2bff) {
        if ((*(char *)(DAT_00048278 + 0x177) != '\0') &&
           ((**(code **)(local_200 + 0x20))
                      (u_Warning__00042cb0,u_Using_a_Level_2_or_higher_policy_00042ae0,3,local_228),
           local_228[0] == '\x01')) {
          if (DAT_00030040 == -1) {
            DAT_00030040 = local_61;
          }
          *(char *)(DAT_00048278 + 0x177) = DAT_00030040;
        }
        DAT_00030040 = *(char *)(DAT_00048278 + 0x177);
      }
      return 0;
    }
    return lVar1;
  }
  return lVar1;
}

