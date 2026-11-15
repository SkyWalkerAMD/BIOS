
char * FUN_0000b5e0(longlong param_1,longlong param_2,short *param_3)

{
  longlong lVar1;
  char *pcVar2;
  undefined1 *puVar3;
  undefined8 *puVar4;
  longlong *plVar5;
  int iVar6;
  ulonglong uVar7;
  undefined8 **local_38;
  undefined8 **local_30;
  
  uVar7 = 0;
  if (((param_1 == 0) || (param_2 == 0)) || (param_3 == (short *)0x0)) {
    pcVar2 = (char *)0x8000000000000002;
  }
  else {
    local_38 = &local_38;
    local_30 = &local_38;
    pcVar2 = (char *)FUN_00009b8c(param_1,(longlong)&local_38);
    if (-1 < (longlong)pcVar2) {
      puVar3 = FUN_00016b80();
      if (puVar3 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar3 + 0x18) = 5;
        FUN_00018744(param_2,s_Storage_0001a618,(longlong)puVar3);
        puVar4 = (undefined8 *)FUN_00016b80();
        if (puVar4 != (undefined8 *)0x0) {
          *(undefined4 *)(puVar4 + 3) = 5;
          if (*(longlong *)(param_1 + 0x330) != 0) {
            do {
              lVar1 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar7 * 8);
              if (*(char *)(lVar1 + 0x18) == '\t') {
                if ((*(byte *)(lVar1 + 0x36) & 1) == 0) {
                  pcVar2 = (char *)0x8000000000000002;
                }
                else {
                  pcVar2 = FUN_0000b4b4(param_1,lVar1 + 0x28,(longlong)puVar3,param_3,
                                        *(longlong *)(lVar1 + 0x10),(longlong)puVar4,
                                        (longlong *)&local_38);
                }
                if ((longlong)pcVar2 < 0) {
                  FUN_00016bcc(puVar4);
                  goto LAB_0000b778;
                }
              }
              uVar7 = uVar7 + 1;
            } while (uVar7 < *(ulonglong *)(param_1 + 0x330));
          }
          plVar5 = (longlong *)puVar4[2];
          iVar6 = 0;
          if (plVar5 != (longlong *)0x0) {
            do {
              plVar5 = (longlong *)*plVar5;
              iVar6 = iVar6 + 1;
            } while (plVar5 != (longlong *)0x0);
            if (0 < iVar6) {
              FUN_00018744(param_2,s_Redundancy_0001ac80,(longlong)puVar4);
            }
          }
          puVar3 = FUN_00016b80();
          if (puVar3 != (undefined1 *)0x0) {
            *(undefined4 *)(puVar3 + 0x18) = 5;
            FUN_00018744(param_2,s_SimpleStorage_0001ac70,(longlong)puVar3);
            pcVar2 = (char *)FUN_0000b31c(param_1,(longlong)puVar3);
            goto LAB_0000b778;
          }
        }
      }
      pcVar2 = (char *)0x8000000000000009;
    }
  }
LAB_0000b778:
  FUN_00000de0((longlong *)&local_38);
  return pcVar2;
}

