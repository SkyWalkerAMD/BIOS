/* {"status": "resolved", "address": "0x778", "name": "FUN_00000778"} */

longlong FUN_00000778(longlong param_1,undefined8 param_2)

{
  char cVar1;
  longlong lVar2;
  uint uVar3;
  char *pcVar4;
  longlong local_res20;
  char *local_28;
  undefined8 local_20;
  undefined1 local_18 [16];
  
  uVar3 = 0;
  local_20 = 0;
  local_res20 = 0;
  local_28 = (char *)0x0;
  lVar2 = (**(code **)(DAT_00007b28 + 0x138))(2,&DAT_00007130,0,&local_20,&local_res20);
  if (lVar2 < 0) {
    lVar2 = (**(code **)(DAT_00007b28 + 0x118))
                      (param_2,&DAT_00007040,local_18,*(undefined8 *)(param_1 + 0x28),param_2,0x10);
    if (lVar2 < 0) {
      return lVar2;
    }
    (**(code **)(DAT_00007b28 + 0x120))
              (param_2,&DAT_00007040,*(undefined8 *)(param_1 + 0x28),param_2);
    lVar2 = (**(code **)(DAT_00007b28 + 0x98))(param_2,&DAT_00007060,&local_28);
    if ((-1 < lVar2) && (cVar1 = *local_28, pcVar4 = local_28, cVar1 != '\x7f')) {
      do {
        if ((cVar1 == -1) && (pcVar4[1] == -1)) break;
        if (cVar1 == '\x03') {
          cVar1 = pcVar4[1];
          if (cVar1 == '\x05') {
            uVar3 = uVar3 | 1;
          }
          else if (cVar1 == '\x0f') {
            uVar3 = uVar3 | 2;
          }
          else if (cVar1 == '\x10') {
            uVar3 = uVar3 | 4;
          }
        }
        pcVar4 = pcVar4 + (ulonglong)(byte)pcVar4[3] * 0x100 + (ulonglong)(byte)pcVar4[2];
        cVar1 = *pcVar4;
      } while (cVar1 != '\x7f');
      if (uVar3 != 0) {
        lVar2 = (**(code **)(DAT_00007b28 + 0x118))
                          (param_2,&DAT_00007130,0,*(undefined8 *)(param_1 + 0x28),param_2,4);
        if (-1 < lVar2) {
          return -0x7ffffffffffffffd;
        }
        if (lVar2 != -0x7ffffffffffffffd) {
          return lVar2;
        }
        return 0;
      }
    }
  }
  else if (local_res20 != 0) {
    (**(code **)(DAT_00007b28 + 0x48))();
  }
  return -0x7ffffffffffffffd;
}

