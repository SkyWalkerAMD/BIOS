
undefined8 FUN_000095ac(longlong param_1,longlong param_2,longlong param_3)

{
  longlong lVar1;
  undefined1 *puVar2;
  undefined8 uVar3;
  ulonglong uVar4;
  longlong *plVar5;
  ulonglong uVar6;
  
  uVar3 = 0;
  if (((param_1 == 0) || (param_2 == 0)) || (param_3 == 0)) {
    uVar3 = 0x8000000000000002;
  }
  else {
    puVar2 = FUN_00016b80();
    if (puVar2 == (undefined1 *)0x0) {
      uVar3 = 0x8000000000000009;
    }
    else {
      *(undefined4 *)(puVar2 + 0x18) = 5;
      FUN_00018744(param_2,s_Devices_0001b548,(longlong)puVar2);
      uVar6 = 0;
      for (plVar5 = (longlong *)(param_1 + 0x10); (uVar6 < 0x14 || (*plVar5 == 0xff));
          plVar5 = plVar5 + 1) {
        uVar4 = 0;
        if (*(ulonglong *)(param_3 + 0x330) != 0) {
          do {
            lVar1 = *(longlong *)(*(longlong *)(param_3 + 0x338) + uVar4 * 8);
            if ((*(char *)(lVar1 + 0x18) == '\x05') && (*plVar5 == *(longlong *)(lVar1 + 0x10))) {
              uVar3 = FUN_0000941c(*(longlong *)(*(longlong *)(param_3 + 0x338) + uVar4 * 8) + 0x28,
                                   (longlong)puVar2);
              break;
            }
            uVar4 = uVar4 + 1;
          } while (uVar4 < *(ulonglong *)(param_3 + 0x330));
        }
        uVar6 = uVar6 + 1;
      }
    }
  }
  return uVar3;
}

