
ulonglong FUN_0000e6a8(longlong param_1,longlong param_2,longlong param_3,undefined8 param_4,
                      ulonglong param_5)

{
  longlong lVar1;
  longlong lVar2;
  longlong *plVar3;
  ulonglong uVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  longlong *plVar7;
  undefined1 *puVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  int iVar11;
  ulonglong uVar12;
  char acStack_168 [304];
  
  uVar10 = 0;
  uVar12 = uVar10;
  if (*(longlong *)(param_2 + 0x330) != 0) {
    do {
      uVar9 = 0;
      if (*(char *)(*(longlong *)(*(longlong *)(param_2 + 0x338) + uVar12 * 8) + 0x18) == '\x03') {
        FUN_00015c2c(acStack_168,300,(byte *)s__s_PCIeDevices__a_0001ad00,param_5);
        uVar4 = uVar9;
        if (param_3 != 0) {
          uVar4 = func_0x00006ba8(param_3,acStack_168);
        }
        if (uVar4 == 0) {
          puVar5 = FUN_00016b80();
          if (puVar5 == (undefined1 *)0x0) {
            return 0x8000000000000009;
          }
          *(undefined4 *)(puVar5 + 0x18) = 6;
          plVar3 = *(longlong **)(param_3 + 0x10);
          if (*(longlong **)(param_3 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(param_3 + 0x10) = puVar5;
          }
          else {
            do {
              plVar7 = plVar3;
              plVar3 = (longlong *)*plVar7;
            } while ((longlong *)*plVar7 != (longlong *)0x0);
            *plVar7 = (longlong)puVar5;
            *(longlong **)(puVar5 + 8) = plVar7;
          }
          puVar6 = FUN_0001880c(acStack_168);
          FUN_00018744((longlong)puVar5,s__odata_id_00019b40,(longlong)puVar6);
          lVar1 = *(longlong *)(*(longlong *)(param_2 + 0x338) + uVar12 * 8);
          if (*(short *)(lVar1 + 0x9c) != 0) {
            if ((*(byte *)(lVar1 + 0x9c) & 6) == 6) {
              puVar6 = FUN_00016b80();
              if (puVar6 == (undefined1 *)0x0) {
                return 0x8000000000000009;
              }
              *(undefined4 *)(puVar6 + 0x18) = 6;
              plVar3 = *(longlong **)(param_1 + 0x10);
              if (*(longlong **)(param_1 + 0x10) == (longlong *)0x0) {
                *(undefined1 **)(param_1 + 0x10) = puVar6;
              }
              else {
                do {
                  plVar7 = plVar3;
                  plVar3 = (longlong *)*plVar7;
                } while ((longlong *)*plVar7 != (longlong *)0x0);
                *plVar7 = (longlong)puVar6;
                *(longlong **)(puVar6 + 8) = plVar7;
              }
              puVar8 = FUN_00016b80();
              if (puVar8 == (undefined1 *)0x0) {
                return 0x8000000000000009;
              }
              *(undefined4 *)(puVar8 + 0x18) = 5;
              FUN_00018744((longlong)puVar6,s_PCIeFunctions_0001acb8,(longlong)puVar8);
              iVar11 = 0;
              uVar10 = 0;
              if (*(ulonglong *)(param_2 + 0x330) != 0) {
                do {
                  lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + uVar10 * 8);
                  if ((((*(char *)(lVar2 + 0x18) == '\x03') && (*(int *)(lVar2 + 0x60) != 0)) &&
                      (*(char *)(lVar1 + 0x33) == *(char *)(lVar2 + 0x33))) &&
                     ((*(char *)(lVar1 + 0x34) == *(char *)(lVar2 + 0x34) &&
                      (((*(byte *)(lVar2 + 0x5c) ^ *(byte *)(lVar1 + 0x5c)) & 0xf8) == 0)))) {
                    iVar11 = iVar11 + 1;
                  }
                  uVar10 = uVar10 + 1;
                } while (uVar10 < *(ulonglong *)(param_2 + 0x330));
              }
              uVar9 = func_0x0000e374(puVar6,lVar1 + 0x28,iVar11);
              if ((-1 < (longlong)uVar9) &&
                 (uVar9 = FUN_00003d30((byte *)(lVar1 + 0xa8),(longlong)puVar6),
                 -1 < (longlong)uVar9)) {
                uVar9 = func_0x0000e18c(param_2,puVar5,puVar8,param_4,param_5,uVar12);
              }
            }
            else {
              uVar9 = 0x8000000000000002;
            }
          }
          uVar10 = uVar9;
          if ((longlong)uVar9 < 0) {
            return uVar9;
          }
        }
      }
      uVar12 = uVar12 + 1;
    } while (uVar12 < *(ulonglong *)(param_2 + 0x330));
  }
  return uVar10;
}

