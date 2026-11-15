
longlong FUN_000004d4(undefined8 param_1,int param_2,char param_3)

{
  short *psVar1;
  ulonglong uVar2;
  longlong lVar3;
  longlong *plVar4;
  undefined4 in_register_00000014;
  ulonglong uVar5;
  longlong lVar6;
  undefined1 local_res10 [8];
  undefined1 local_res20 [8];
  undefined1 local_48 [4];
  byte local_44;
  byte local_43;
  undefined1 local_42;
  byte local_41;
  undefined2 local_40;
  char local_38 [16];
  
  uVar5 = CONCAT44(in_register_00000014,param_2);
  lVar6 = (longlong)param_2;
  if (param_2 - 1U < 3) {
    uVar2 = 0;
    if ((param_2 == 1) && (uVar5 = *(ulonglong *)(DAT_000011c8 + 0x68), uVar5 != 0)) {
      plVar4 = *(longlong **)(DAT_000011c8 + 0x70);
      do {
        if ((DAT_00001150 == *plVar4) && (DAT_00001158 == plVar4[1])) {
          psVar1 = (short *)(*(longlong **)(DAT_000011c8 + 0x70))[uVar2 * 3 + 2];
          if (psVar1 != (short *)0x0) {
            if (*psVar1 != 1) {
              return -0x7ffffffffffffff2;
            }
            if (*(int *)(psVar1 + 6) == 0x20) {
              return -0x7ffffffffffffffd;
            }
          }
          break;
        }
        uVar2 = uVar2 + 1;
        plVar4 = plVar4 + 3;
      } while (uVar2 < uVar5);
    }
    if (DAT_000011c0 != '\0') {
      local_res20[0] = 9;
      lVar3 = (**(code **)(DAT_00001468 + 8))
                        (DAT_00001468,CONCAT71((int7)(uVar5 >> 8),6),0,0x25,0,0,local_38,local_res20
                        );
      if (lVar3 < 0) {
        return lVar3;
      }
      if (local_38[0] != '\0') {
        return lVar3;
      }
      if (*(short *)(&DAT_00001480 + lVar6 * 6) == 0) {
        return -0x7fffffffffffffee;
      }
      FUN_00000260((undefined8 *)&local_44,6);
      local_44 = local_44 & 0x38 | (byte)param_2 & 7;
      local_43 = ((&DAT_00001483)[lVar6 * 6] & 7) << 4 | (&DAT_00001484)[lVar6 * 6] & 7 |
                 local_43 & 0x88;
      local_42 = (&DAT_00001482)[lVar6 * 6];
      if (param_3 == '\0') {
        if (param_2 == 1) {
          local_41 = local_41 | 2;
        }
        else if (param_2 == 2) {
          local_41 = local_41 | 4;
        }
        else if (param_2 == 3) {
          local_41 = local_41 | 8;
        }
      }
      else {
        local_41 = local_41 | 0x3e;
      }
      local_40 = *(undefined2 *)(&DAT_00001480 + lVar6 * 6);
      local_res20[0] = 6;
      local_res10[0] = 1;
      lVar6 = (**(code **)(DAT_00001468 + 8))
                        (DAT_00001468,6,0,0x24,&local_44,6,local_48,local_res10);
      if (-1 < lVar6) {
        local_48[0] = 0;
        local_res10[0] = 1;
        lVar6 = (**(code **)(DAT_00001468 + 8))(DAT_00001468,6,0,0x22,0,0,local_48,local_res10);
        return lVar6;
      }
      return lVar6;
    }
  }
  return -0x7ffffffffffffffd;
}

