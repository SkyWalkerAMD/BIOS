
undefined8 FUN_00009b8c(longlong param_1,longlong param_2)

{
  ulonglong uVar1;
  longlong *plVar2;
  char cVar3;
  longlong lVar4;
  undefined8 uVar5;
  undefined8 *puVar6;
  undefined1 *puVar7;
  ulonglong uVar8;
  char *pcVar9;
  char *pcVar10;
  ulonglong uVar11;
  
  uVar11 = 0;
  if (*(longlong *)(param_1 + 0x330) != 0) {
    do {
      lVar4 = *(longlong *)(*(longlong *)(param_1 + 0x338) + uVar11 * 8);
      if ((*(char *)(lVar4 + 0x18) == '\x05') && (*(int *)(lVar4 + 0x100) < 3)) {
        uVar5 = *(undefined8 *)(lVar4 + 0x10);
        pcVar10 = *(char **)(lVar4 + 0x630);
        puVar7 = (undefined1 *)FUN_00015ad4(0x28);
        if (puVar7 == (undefined1 *)0x0) {
          return 0x8000000000000009;
        }
        *puVar7 = 5;
        *(undefined8 *)(puVar7 + 8) = uVar5;
        uVar8 = 0;
        cVar3 = *pcVar10;
        while (cVar3 != '\0') {
          uVar8 = uVar8 + 1;
          cVar3 = pcVar10[uVar8];
        }
        uVar1 = uVar8 + 1;
        pcVar9 = (char *)FUN_00015ad4(uVar1);
        *(char **)(puVar7 + 0x10) = pcVar9;
        if (((pcVar9 != (char *)0x0) && (uVar8 < 1000000)) &&
           (uVar8 = FUN_00015bd0(pcVar10,uVar1), uVar8 < uVar1)) {
          if (pcVar9 < pcVar10) {
LAB_00009c5e:
            if (pcVar9 + uVar1 <= pcVar10) {
LAB_00009c72:
              for (; *pcVar10 != '\0'; pcVar10 = pcVar10 + 1) {
                *pcVar9 = *pcVar10;
                pcVar9 = pcVar9 + 1;
              }
              *pcVar9 = '\0';
            }
          }
          else if (pcVar10 + uVar8 + 1 <= pcVar9) {
            if (pcVar9 <= pcVar10) goto LAB_00009c5e;
            goto LAB_00009c72;
          }
        }
        plVar2 = (longlong *)(puVar7 + 0x18);
        *plVar2 = param_2;
        puVar6 = *(undefined8 **)(param_2 + 8);
        *(undefined8 **)(puVar7 + 0x20) = puVar6;
        *puVar6 = plVar2;
        *(longlong **)(param_2 + 8) = plVar2;
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < *(ulonglong *)(param_1 + 0x330));
  }
  return 0;
}

