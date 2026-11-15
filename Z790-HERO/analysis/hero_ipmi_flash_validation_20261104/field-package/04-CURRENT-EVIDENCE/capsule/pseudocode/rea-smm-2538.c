
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00002538(undefined8 param_1,longlong param_2)

{
  undefined8 uVar1;
  longlong lVar2;
  ulonglong uVar3;
  char local_res18 [8];
  longlong local_res20;
  byte local_68 [4];
  int local_64;
  undefined4 uStack_60;
  undefined4 uStack_5c;
  undefined4 local_53;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 *local_38;
  undefined8 *local_30;
  undefined8 local_28;
  undefined8 local_20;
  ulonglong local_18 [2];
  
  local_48 = 5;
  local_38 = (undefined8 *)0x0;
  local_68[0] = 0x4c;
  local_68[1] = 0xf2;
  local_68[2] = 0x39;
  local_68[3] = 0x77;
  local_64 = 0x11d493d7;
  uStack_60 = 0x90003a9a;
  uStack_5c = 0x4dc13f27;
  local_40 = 0;
  local_28 = 0;
  if (DAT_00005830 == 0) {
    DAT_00005818 = *(longlong *)(param_2 + 0x60);
    DAT_00005820 = *(longlong *)(param_2 + 0x58);
    DAT_00005830 = param_2;
  }
  if ((((DAT_00005860 != (undefined8 *)0x0) ||
       (lVar2 = (**(code **)(DAT_00005818 + 0x140))(&DAT_00005280,0,&DAT_00005860), -1 < lVar2)) &&
      ((*(code *)*DAT_00005860)(DAT_00005860,local_res18), local_res18[0] != '\0')) &&
     (lVar2 = (*(code *)DAT_00005860[1])(DAT_00005860,&DAT_00005828), -1 < lVar2)) {
    lVar2 = FUN_000045f0();
    DAT_00005838 = 1;
    if (lVar2 != 0) {
      DAT_00005820 = lVar2;
    }
    DAT_00005848 = 0;
    FUN_00004484();
    FUN_0000450c();
    DAT_00005848 = 1;
  }
  lVar2 = FUN_0000442c(DAT_00005830,(longlong *)local_68);
  if (lVar2 == 0) {
    lVar2 = -0x7fffffffffffffff;
  }
  else {
    DAT_00005988 = *(int *)(lVar2 + 0xc);
    lVar2 = (**(code **)(DAT_00005828 + 0xd0))(&DAT_00005090,0,&DAT_00005a40);
    if ((-1 < lVar2) && (DAT_00005a40 != 0)) {
      DAT_00005a78 = 0;
      DAT_00005a70 = 0;
      lVar2 = (**(code **)(DAT_00005a40 + 0x18))(DAT_00005a40,&DAT_00005a60,&DAT_00005110,0,0);
      if ((lVar2 < 0) || (DAT_00005a78 == 0)) {
        if (lVar2 == -0x7ffffffffffffffb) {
          lVar2 = 0;
        }
      }
      else {
        lVar2 = (**(code **)(*(longlong *)(DAT_00005830 + 0x60) + 0x28))(0,0,0x2001,&DAT_000057b8);
        if (-1 < lVar2) {
          FUN_0000489e(DAT_000057b8,0x2001000,0);
          lVar2 = (**(code **)(DAT_00005828 + 0x50))(6,0x40000,&DAT_000057a8);
          if (-1 < lVar2) {
            FUN_0000489e(DAT_000057a8,0x40000,0xdb);
            DAT_000057d0 = 0x5c;
            lVar2 = (**(code **)(*(longlong *)(DAT_00005830 + 0x60) + 0x28))(0,0,1,&DAT_000057d8);
            if (-1 < lVar2) {
              FUN_0000489e(DAT_000057d8,DAT_000057d0,0);
              lVar2 = (**(code **)(DAT_00005828 + 0xd0))(&DAT_00005160,0,&local_30);
              if (-1 < lVar2) {
                if (((local_30 == (undefined8 *)0x0) ||
                    (((DAT_000051a0 & 2) == 0 && ((DAT_000051a1 & 2) == 0)))) ||
                   (lVar2 = (*(code *)*local_30)(local_30,&LAB_00001684,&local_48,&local_40),
                   -1 < lVar2)) {
                  FUN_0000220c(param_2);
                  local_res20 = 0;
                  lVar2 = (**(code **)(DAT_00005828 + 0xd0))(&DAT_00005020,0,&local_res20);
                  if (((-1 < lVar2) ||
                      (lVar2 = (**(code **)(DAT_00005818 + 0x140))(&DAT_00005020,0,&local_res20),
                      -1 < lVar2)) && (local_res20 != 0)) {
                    DAT_00005a90 = *(undefined8 *)(local_res20 + 0x10);
                    DAT_00005a80 = *(undefined8 *)(local_res20 + 0x18);
                    DAT_00005a88 = *(undefined8 *)(local_res20 + 8);
                    *(undefined1 **)(local_res20 + 0x10) = &LAB_000020b8;
                    *(undefined1 **)(local_res20 + 0x18) = &LAB_000020f8;
                    *(undefined1 **)(local_res20 + 8) = &LAB_00002138;
                    DAT_00005210 = DAT_000057b8;
                    _DAT_00005220 = DAT_000057a8;
                    DAT_00005218 = 0;
                    DAT_00005228 = 0;
                    (**(code **)(DAT_00005828 + 0xa8))(&local_28,&DAT_00005080,0,&PTR_FUN_000051f0);
                    DAT_000057b0 = 0;
                    if (((DAT_00005988 == 0x12) || (DAT_00005988 == 0x20)) &&
                       ((lVar2 = FUN_000043e0((longlong *)&DAT_00005000), lVar2 != 0 &&
                        (*(char *)(lVar2 + 0x20) == '\0')))) {
                      uVar1 = *(undefined8 *)(lVar2 + 0x18);
                      DAT_000057b0 = *(int *)(lVar2 + 0x21) == 4;
                      local_64._1_3_ = (uint3)uVar1;
                      uStack_60 = (undefined4)((ulonglong)uVar1 >> 0x18);
                      uStack_5c._0_1_ = (undefined1)((ulonglong)uVar1 >> 0x38);
                      local_53 = *(undefined4 *)(lVar2 + 0x25);
                      local_64 = (uint)local_64._1_3_ << 8;
                      local_68[0] = 4;
                      local_68[1] = 2;
                      local_68[2] = 0;
                      local_68[3] = 0;
                      FUN_000019d0(local_68);
                    }
                    DAT_000051a2 = 1;
                    local_20 = 0;
                    lVar2 = (**(code **)(DAT_00005828 + 0xc0))
                                      (&DAT_00005120,&LAB_00002408,&local_20);
                    if (((-1 < lVar2) &&
                        (lVar2 = (**(code **)(DAT_00005828 + 0xd0))(&DAT_00005180,0,&local_38),
                        -1 < lVar2)) &&
                       (lVar2 = (**(code **)(DAT_00005828 + 0xd0))(&DAT_00005050,0,&DAT_00005990),
                       -1 < lVar2)) {
                      uVar3 = 0x1d;
                      do {
                        local_18[0] = uVar3;
                        lVar2 = (*(code *)*local_38)(local_38,FUN_0000241c,local_18,&local_40);
                        if (lVar2 < 0) break;
                        uVar3 = uVar3 + 1;
                      } while (uVar3 < 0x20);
                    }
                  }
                }
                lVar2 = 0;
              }
            }
          }
        }
      }
    }
  }
  return lVar2;
}

