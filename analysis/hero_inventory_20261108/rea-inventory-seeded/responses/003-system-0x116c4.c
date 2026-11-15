
ulonglong SerializeMemoryB_from_disassembly(longlong param_1,longlong param_2)

{
  longlong lVar1;
  longlong *plVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  longlong *plVar5;
  ulonglong uVar6;
  undefined1 *puVar7;
  byte *pbVar8;
  ulonglong uVar9;
  
  uVar6 = 0;
  puVar3 = FUN_00016b80();
  if (puVar3 == (undefined1 *)0x0) {
LAB_00011824:
    uVar6 = 0x8000000000000009;
  }
  else {
    *(undefined4 *)(puVar3 + 0x18) = 5;
    FUN_00018744(param_2,s_MemoryDomains_0001aca8,(longlong)puVar3);
    uVar9 = uVar6;
    if (*(longlong *)(param_1 + 0x330) != 0) {
      do {
        lVar1 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar9 * 8);
        if (*(char *)(lVar1 + 0x18) == '\b') {
          pbVar8 = (byte *)(lVar1 + 0x28);
          if (*(short *)(lVar1 + 0x158) != 0) {
            if (((*(byte *)(lVar1 + 0x159) & 1) == 0) || ((*(byte *)(lVar1 + 0x159) & 2) == 0)) {
              return 0x800000000000000e;
            }
            puVar4 = FUN_00016b80();
            if (puVar4 != (undefined1 *)0x0) {
              *(undefined4 *)(puVar4 + 0x18) = 6;
              plVar2 = *(longlong **)(puVar3 + 0x10);
              if (*(longlong **)(puVar3 + 0x10) == (longlong *)0x0) {
                *(undefined1 **)(puVar3 + 0x10) = puVar4;
              }
              else {
                do {
                  plVar5 = plVar2;
                  plVar2 = (longlong *)*plVar5;
                } while ((longlong *)*plVar5 != (longlong *)0x0);
                *plVar5 = (longlong)puVar4;
                *(longlong **)(puVar4 + 8) = plVar5;
              }
              uVar6 = FUN_00011560(pbVar8,(longlong)puVar4);
              if ((longlong)uVar6 < 0) {
                return uVar6;
              }
              uVar6 = FUN_00010d78((longlong)pbVar8,(longlong)puVar4,param_1,(longlong *)0x0);
              if ((longlong)uVar6 < 0) {
                return uVar6;
              }
              puVar7 = FUN_00016b80();
              if (puVar7 != (undefined1 *)0x0) {
                *(undefined4 *)(puVar7 + 0x18) = 5;
                FUN_00018744((longlong)puVar4,s_MemoryChunks_0001ac98,(longlong)puVar7);
                uVar6 = FUN_00011438((longlong)pbVar8,param_1,(longlong)puVar7);
                if ((longlong)uVar6 < 0) {
                  return uVar6;
                }
                goto LAB_00011807;
              }
            }
            goto LAB_00011824;
          }
        }
        else {
LAB_00011807:
          uVar9 = uVar9 + 1;
        }
      } while (uVar9 < *(ulonglong *)(param_1 + 0x330));
    }
  }
  return uVar6;
}

