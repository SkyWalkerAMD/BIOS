
ulonglong FUN_0000e18c(longlong param_1,undefined8 *param_2,longlong param_3,longlong param_4,
                      ulonglong param_5,ulonglong param_6)

{
  longlong lVar1;
  char *pcVar2;
  longlong *plVar3;
  undefined8 *puVar4;
  longlong lVar5;
  undefined1 *puVar6;
  longlong *plVar7;
  undefined1 *puVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  char local_158 [304];
  
  uVar9 = 0;
  if ((((param_1 == 0) || (param_2 == (undefined8 *)0x0)) || (param_3 == 0)) ||
     ((param_4 == 0 || (param_5 == 0)))) {
    uVar9 = 0x8000000000000002;
  }
  else {
    puVar4 = FUN_000186b4((longlong)param_2,s__odata_id_00019b40);
    if (puVar4 == (undefined8 *)0x0) {
      uVar9 = 0x800000000000000e;
    }
    else {
      for (; param_6 < *(ulonglong *)(param_1 + 0x330); param_6 = param_6 + 1) {
        lVar1 = *(longlong *)(*(longlong *)(param_1 + 0x338) + param_6 * 8);
        if (*(char *)(lVar1 + 0x18) == '\x03') {
          FUN_00015c2c(local_158,300,(byte *)s__s_PCIeDevices__a_PCIeFunctions__0001acd8,param_5);
          pcVar2 = (char *)puVar4[5];
          uVar10 = 0;
          if (*pcVar2 != '\0') {
            do {
              uVar10 = uVar10 + 1;
            } while (pcVar2[uVar10] != '\0');
            if ((uVar10 != 0) && (lVar5 = thunk_FUN_00015b92(local_158,pcVar2,uVar10), lVar5 != 0))
            goto LAB_0000e335;
          }
          puVar6 = FUN_00016b80();
          if (puVar6 == (undefined1 *)0x0) {
            return 0x8000000000000009;
          }
          *(undefined4 *)(puVar6 + 0x18) = 6;
          plVar3 = *(longlong **)(param_4 + 0x10);
          if (*(longlong **)(param_4 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(param_4 + 0x10) = puVar6;
          }
          else {
            do {
              plVar7 = plVar3;
              plVar3 = (longlong *)*plVar7;
            } while ((longlong *)*plVar7 != (longlong *)0x0);
            *plVar7 = (longlong)puVar6;
            *(longlong **)(puVar6 + 8) = plVar7;
          }
          puVar8 = FUN_0001880c(local_158);
          FUN_00018744((longlong)puVar6,s__odata_id_00019b40,(longlong)puVar8);
          uVar9 = FUN_0000e078(param_3,lVar1 + 0x28,param_2,local_158,param_1,
                               *(longlong *)
                                (*(longlong *)(*(longlong *)(param_1 + 0x338) + param_6 * 8) + 0x10)
                              );
          if ((longlong)uVar9 < 0) {
            return uVar9;
          }
        }
LAB_0000e335:
      }
    }
  }
  return uVar9;
}

