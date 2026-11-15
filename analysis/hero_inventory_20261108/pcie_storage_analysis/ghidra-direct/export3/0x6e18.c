
ulonglong FUN_00006e18(undefined8 *param_1,longlong param_2,ulonglong param_3,undefined8 *param_4,
                      longlong param_5,byte *param_6,ulonglong param_7)

{
  longlong *plVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined1 *puVar4;
  longlong lVar5;
  longlong *plVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  undefined8 *local_res10;
  byte local_168 [304];
  
  uVar7 = 0;
  lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + param_3 * 8);
  if (*(short *)(lVar2 + 0x9c) != 0) {
    if ((*(byte *)(lVar2 + 0x9c) & 6) == 6) {
      local_res10 = (undefined8 *)FUN_00016b80();
      if (local_res10 == (undefined8 *)0x0) {
        return 0x8000000000000009;
      }
      *(undefined4 *)(local_res10 + 3) = 5;
      uVar7 = param_3;
      if (param_3 < *(ulonglong *)(param_2 + 0x330)) {
        do {
          uVar8 = 0;
          if (*(char *)(*(longlong *)(*(longlong *)(param_2 + 0x338) + uVar7 * 8) + 0x18) == '\x03')
          {
            FUN_00015c2c((char *)local_168,300,(byte *)s__s_PCIeDevices__a_PCIeFunctions__0001acd8,
                         param_7);
            if (*param_6 != 0) {
              do {
                uVar8 = uVar8 + 1;
              } while (param_6[uVar8] != 0);
              if ((uVar8 != 0) &&
                 (lVar2 = thunk_FUN_00015b92((char *)local_168,(char *)param_6,uVar8), lVar2 != 0))
              goto LAB_00006fc0;
            }
            puVar3 = (undefined8 *)FUN_00016b80();
            if (puVar3 == (undefined8 *)0x0) {
              uVar7 = 0x8000000000000009;
              goto LAB_000070e1;
            }
            *(undefined4 *)(puVar3 + 3) = 6;
            plVar1 = *(longlong **)(param_5 + 0x10);
            if (*(longlong **)(param_5 + 0x10) == (longlong *)0x0) {
              *(undefined8 **)(param_5 + 0x10) = puVar3;
            }
            else {
              do {
                plVar6 = plVar1;
                plVar1 = (longlong *)*plVar6;
              } while ((longlong *)*plVar6 != (longlong *)0x0);
              *plVar6 = (longlong)puVar3;
              puVar3[1] = plVar6;
            }
            puVar4 = FUN_0001880c((char *)local_168);
            FUN_00018744((longlong)puVar3,s__odata_id_00019b40,(longlong)puVar4);
            puVar3 = FUN_000186f0(puVar3);
            if (puVar3 != (undefined8 *)0x0) {
              plVar1 = (longlong *)local_res10[2];
              if ((longlong *)local_res10[2] == (longlong *)0x0) {
                local_res10[2] = puVar3;
              }
              else {
                do {
                  plVar6 = plVar1;
                  plVar1 = (longlong *)*plVar6;
                } while ((longlong *)*plVar6 != (longlong *)0x0);
                *plVar6 = (longlong)puVar3;
                puVar3[1] = plVar6;
              }
            }
          }
LAB_00006fc0:
          uVar7 = uVar7 + 1;
        } while (uVar7 < *(ulonglong *)(param_2 + 0x330));
      }
      uVar7 = FUN_000069c8(param_1,*(longlong *)(*(longlong *)(param_2 + 0x338) + param_3 * 8) +
                                   0x28,local_res10,param_6);
      if ((-1 < (longlong)uVar7) && (param_3 < *(ulonglong *)(param_2 + 0x330))) {
        do {
          lVar2 = *(longlong *)(*(longlong *)(param_2 + 0x338) + param_3 * 8);
          if (*(char *)(lVar2 + 0x18) == '\x03') {
            FUN_00015c2c((char *)local_168,300,(byte *)s__s_PCIeDevices__a_PCIeFunctions__0001acd8,
                         param_7);
            uVar8 = 0;
            if (*param_6 != 0) {
              do {
                uVar8 = uVar8 + 1;
              } while (param_6[uVar8] != 0);
              if ((uVar8 != 0) &&
                 (lVar5 = thunk_FUN_00015b92((char *)local_168,(char *)param_6,uVar8), lVar5 != 0))
              goto LAB_000070b1;
            }
            uVar7 = FUN_00006c74(param_1,lVar2 + 0x28,param_4,local_168);
            if ((longlong)uVar7 < 0) break;
          }
LAB_000070b1:
          param_3 = param_3 + 1;
        } while (param_3 < *(ulonglong *)(param_2 + 0x330));
      }
    }
    else {
      uVar7 = 0x8000000000000002;
    }
  }
LAB_000070e1:
  if (local_res10 != (undefined8 *)0x0) {
    FUN_00016bcc(local_res10);
  }
  return uVar7;
}

