
ulonglong SerializeMemoryA_from_disassembly(longlong param_1,longlong param_2)

{
  int iVar1;
  longlong lVar2;
  longlong *plVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  longlong *plVar6;
  ulonglong uVar7;
  undefined1 *puVar8;
  byte bVar9;
  byte bVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  ulonglong local_res8;
  longlong local_res10;
  ulonglong local_res18;
  
  uVar12 = 0;
  local_res8 = 0;
  local_res18 = 0;
  bVar9 = 0;
  if ((param_1 == 0) || (param_2 == 0)) {
    return 0x8000000000000002;
  }
  local_res10 = param_2;
  puVar4 = FUN_00016b80();
  if (puVar4 == (undefined1 *)0x0) {
    return 0x8000000000000009;
  }
  *(undefined4 *)(puVar4 + 0x18) = 5;
  FUN_00018744(param_2,s_Memory_0001a7e8,(longlong)puVar4);
  uVar7 = uVar12;
  uVar11 = uVar12;
  bVar10 = 0;
  if (*(longlong *)(param_1 + 0x330) != 0) {
    do {
      lVar2 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar12 * 8);
      if (*(char *)(lVar2 + 0x18) == '\x02') {
        bVar9 = bVar10;
        if (*(longlong *)(lVar2 + 0x148) != 0) {
          if ((*(byte *)(lVar2 + 0x14d) & 1) != 0) {
            iVar1 = *(int *)(lVar2 + 0x130);
            if (iVar1 == 0) {
              bVar10 = bVar10 | 1;
            }
            else if (iVar1 == 1) {
              bVar10 = bVar10 | 2;
            }
            else if (iVar1 == 2) {
              bVar10 = bVar10 | 4;
            }
          }
          puVar5 = FUN_00016b80();
          if (puVar5 == (undefined1 *)0x0) {
            return 0x8000000000000009;
          }
          *(undefined4 *)(puVar5 + 0x18) = 6;
          plVar3 = *(longlong **)(puVar4 + 0x10);
          if (*(longlong **)(puVar4 + 0x10) == (longlong *)0x0) {
            *(undefined1 **)(puVar4 + 0x10) = puVar5;
          }
          else {
            do {
              plVar6 = plVar3;
              plVar3 = (longlong *)*plVar6;
            } while ((longlong *)*plVar6 != (longlong *)0x0);
            *plVar6 = (longlong)puVar5;
            *(longlong **)(puVar5 + 8) = plVar6;
          }
          uVar7 = FUN_000102c0((byte *)(lVar2 + 0x28),(longlong *)&local_res8,
                               (longlong *)&local_res18,(longlong)puVar5);
          if ((longlong)uVar7 < 0) {
            return uVar7;
          }
          uVar7 = FUN_00003d30((byte *)(lVar2 + 0x290),(longlong)puVar5);
          if ((longlong)uVar7 < 0) {
            return uVar7;
          }
          if ((*(char *)(lVar2 + 0x2b) != '\0') && (*(longlong *)(lVar2 + 0x148) != 0)) {
            puVar8 = FUN_00016b80();
            if (puVar8 == (undefined1 *)0x0) {
              return 0x8000000000000009;
            }
            *(undefined4 *)(puVar8 + 0x18) = 6;
            FUN_00018744((longlong)puVar5,s_Metrics_0001ac90,(longlong)puVar8);
            uVar7 = FUN_0000fc8c((undefined8 *)(lVar2 + 0x178),(longlong)puVar8);
            if ((longlong)uVar7 < 0) {
              return uVar7;
            }
          }
          goto LAB_00011b24;
        }
      }
      else {
LAB_00011b24:
        uVar12 = uVar12 + 1;
        bVar9 = bVar10;
      }
      uVar7 = local_res8;
      param_2 = local_res10;
      uVar11 = local_res18;
      bVar10 = bVar9;
    } while (uVar12 < *(ulonglong *)(param_1 + 0x330));
  }
  uVar12 = FUN_00011850(param_2,uVar7,uVar11,bVar9);
  return uVar12;
}

