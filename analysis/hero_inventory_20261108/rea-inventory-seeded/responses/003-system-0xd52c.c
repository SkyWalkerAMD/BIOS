
ulonglong SerializeProcessor_from_disassembly(longlong param_1,longlong param_2)

{
  int iVar1;
  longlong lVar2;
  undefined1 *puVar3;
  ulonglong uVar4;
  char *pcVar5;
  longlong lVar6;
  byte bVar7;
  ulonglong uVar8;
  char *local_res8;
  
  uVar4 = 0;
  uVar8 = 0;
  local_res8 = (char *)0x0;
  lVar6 = 0;
  bVar7 = 0;
  if ((param_1 == 0) || (param_2 == 0)) {
    uVar4 = 0x8000000000000002;
    pcVar5 = (char *)0x0;
  }
  else {
    puVar3 = FUN_00016b80();
    if (puVar3 == (undefined1 *)0x0) {
      return 0x8000000000000009;
    }
    *(undefined4 *)(puVar3 + 0x18) = 5;
    FUN_00018744(param_2,s_Processors_0001a1c0,(longlong)puVar3);
    if (*(longlong *)(param_1 + 0x330) == 0) {
      return 0;
    }
    do {
      lVar2 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar8 * 8);
      if (*(char *)(lVar2 + 0x18) == '\x01') {
        if ((*(byte *)(lVar2 + 0xee) & 0x10) != 0) {
          iVar1 = *(int *)(lVar2 + 0xe0);
          if (iVar1 == 0) {
            bVar7 = bVar7 | 1;
          }
          else if (iVar1 == 1) {
            bVar7 = bVar7 | 2;
          }
          else if (iVar1 == 2) {
            bVar7 = bVar7 | 4;
          }
        }
        uVar4 = FUN_0000d29c((byte *)(lVar2 + 0x28),(longlong *)&local_res8,(longlong)puVar3);
        pcVar5 = local_res8;
        if ((longlong)uVar4 < 0) goto LAB_0000d648;
        lVar6 = lVar6 + 1;
      }
      pcVar5 = local_res8;
      uVar8 = uVar8 + 1;
    } while (uVar8 < *(ulonglong *)(param_1 + 0x330));
    if (lVar6 != 0) {
      uVar4 = FUN_0000d3d0(param_2,local_res8,lVar6,bVar7);
    }
  }
LAB_0000d648:
  if (pcVar5 != (char *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pcVar5);
  }
  return uVar4;
}

