
ulonglong FUN_0000710c(undefined8 *param_1,longlong param_2,longlong param_3,longlong param_4,
                      ulonglong param_5)

{
  longlong *plVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  byte local_148 [304];
  
  uVar5 = 0;
  uVar6 = 0;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      if (*(char *)(*(longlong *)(*(longlong *)(param_2 + 0x338) + uVar6 * 8) + 0x18) == '\x03') {
        FUN_00015c2c((char *)local_148,300,(byte *)s__s_PCIeDevices__a_0001ad00,param_5);
        if (param_3 == 0) {
          puVar2 = (undefined8 *)0x0;
        }
        else {
          puVar2 = FUN_00006ba8(param_3,(char *)local_148);
        }
        if (puVar2 == (undefined8 *)0x0) {
          puVar2 = (undefined8 *)FUN_00016b80();
          if (puVar2 == (undefined8 *)0x0) {
            return 0x8000000000000009;
          }
          *(undefined4 *)(puVar2 + 3) = 6;
          plVar1 = *(longlong **)(param_3 + 0x10);
          if (*(longlong **)(param_3 + 0x10) == (longlong *)0x0) {
            *(undefined8 **)(param_3 + 0x10) = puVar2;
          }
          else {
            do {
              plVar3 = plVar1;
              plVar1 = (longlong *)*plVar3;
            } while ((longlong *)*plVar3 != (longlong *)0x0);
            *plVar3 = (longlong)puVar2;
            puVar2[1] = plVar3;
          }
          puVar4 = FUN_0001880c((char *)local_148);
          FUN_00018744((longlong)puVar2,s__odata_id_00019b40,(longlong)puVar4);
          uVar5 = FUN_00006e18(param_1,param_2,uVar6,puVar2,param_4,local_148,param_5);
          if ((longlong)uVar5 < 0) {
            return uVar5;
          }
        }
      }
      uVar6 = uVar6 + 1;
    } while (uVar6 < *(ulonglong *)(param_2 + 0x330));
  }
  return uVar5;
}

