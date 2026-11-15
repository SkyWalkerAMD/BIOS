
longlong Observed_FrameInput(longlong param_1,longlong param_2)

{
  int iVar1;
  longlong lVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  undefined8 *puVar5;
  char *pcVar6;
  char cVar7;
  longlong *plVar8;
  longlong lVar9;
  longlong *plVar10;
  uint uVar11;
  undefined8 local_48;
  undefined8 uStack_40;
  undefined4 local_38;
  
  plVar10 = (longlong *)0x0;
  lVar9 = -0x7ffffffffffffffd;
  if (*(int *)(param_1 + 0x3c) == 0) {
    return -0x7ffffffffffffffd;
  }
  plVar8 = plVar10;
  if (*(int *)(param_1 + 0x44) != -1) {
    plVar8 = (longlong *)(*(longlong *)(param_1 + 0x48) + (ulonglong)*(uint *)(param_1 + 0x44) * 8);
  }
  if (*(short *)(param_2 + 8) == 1) {
    if ((plVar8 != (longlong *)0x0) && ((*(byte *)(*plVar8 + 0x3c) & 1) != 0)) {
      lVar9 = (**(code **)(*(longlong *)*plVar8 + 0x20))();
      if (lVar9 == -0x7fffffffffffffeb) {
        return -0x7fffffffffffffeb;
      }
      if (-1 < lVar9) {
        return lVar9;
      }
    }
    local_48 = *(undefined8 *)(param_2 + 0xc);
    uStack_40 = *(undefined8 *)(param_2 + 0x14);
    local_38 = *(undefined4 *)(param_2 + 0x1c);
    pcVar6 = (char *)&local_48;
    uVar3 = FUN_0000ff10((undefined8 *)pcVar6);
    if ((int)uVar3 == 0) {
      local_48 = *(undefined8 *)(param_2 + 0xc);
      uStack_40 = *(undefined8 *)(param_2 + 0x14);
      local_38 = *(undefined4 *)(param_2 + 0x1c);
      pcVar6 = (char *)&local_48;
      uVar4 = FUN_00021e68(pcVar6);
      if ((char)uVar4 != '\0') goto LAB_0002200f;
    }
    else {
LAB_0002200f:
      puVar5 = FUN_00059b50(pcVar6,0x30);
      if (puVar5 != (undefined8 *)0x0) {
        (**(code **)(DAT_000afbc8 + 0x160))(puVar5,param_2,0x30);
      }
      local_38 = *(undefined4 *)(param_2 + 0x1c);
      local_48 = *(undefined8 *)(param_2 + 0xc);
      uStack_40 = *(undefined8 *)(param_2 + 0x14);
      uVar3 = FUN_0000ff10(&local_48);
      if ((*(int *)(param_1 + 0x20) == 0) &&
         (uVar4 = FUN_000495f4((ulonglong)
                               *(uint *)(DAT_000baaf0 + 4 +
                                        (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 4) +
                               DAT_000babc0), (char)uVar4 != '\0')) {
        if ((*(short *)(param_2 + 8) != 0) && (((int)uVar3 - 1U < 2 || ((int)uVar3 == 0xd)))) {
          (*(code *)PTR_FUN_00093dd8)(param_2);
          goto LAB_000220a0;
        }
        if (puVar5 == (undefined8 *)0x0) goto LAB_000220b2;
        (**(code **)(DAT_000afbc8 + 0x160))(param_2,puVar5,0x30);
      }
      else {
LAB_000220a0:
        if (puVar5 == (undefined8 *)0x0) goto LAB_000220b2;
      }
      (**(code **)(DAT_000afbc8 + 0x48))(puVar5);
    }
LAB_000220b2:
    local_48 = *(undefined8 *)(param_2 + 0xc);
    uStack_40 = *(undefined8 *)(param_2 + 0x14);
    local_38 = *(undefined4 *)(param_2 + 0x1c);
    uVar3 = FUN_0000ff10(&local_48);
    iVar1 = (int)uVar3;
    if (iVar1 == 3) {
      cVar7 = '\x01';
    }
    else {
      if (iVar1 != 4) {
        if (iVar1 == 5) {
          lVar9 = FUN_00023108(param_1);
          return lVar9;
        }
        if (iVar1 == 6) {
          lVar9 = FUN_00023194(param_1);
          return lVar9;
        }
        if (iVar1 == 0x12) {
          do {
            lVar9 = FUN_00023108(param_1);
          } while (*(int *)(param_1 + 0x5c) != 0);
          return lVar9;
        }
        if (iVar1 == 0x13) {
          do {
            lVar9 = FUN_00023194(param_1);
          } while (*(uint *)(param_1 + 0x60) < *(int *)(param_1 + 0x3c) - 1U);
          return lVar9;
        }
        goto LAB_00021f97;
      }
      cVar7 = '\0';
    }
    lVar9 = FUN_000223e0(param_1,cVar7);
  }
  else {
    if (*(short *)(param_2 + 8) != 2) {
      return -0x7ffffffffffffffd;
    }
    puVar5 = *(undefined8 **)(param_1 + 0x48);
    if (*(int *)(param_1 + 0x3c) != 0) {
      do {
        lVar2 = (**(code **)(*(longlong *)*puVar5 + 0x20))((longlong *)*puVar5,param_2);
        puVar5 = puVar5 + 1;
        if (lVar9 != 0) {
          lVar9 = lVar2;
        }
        uVar11 = (int)plVar10 + 1;
        plVar10 = (longlong *)(ulonglong)uVar11;
      } while (uVar11 < *(uint *)(param_1 + 0x3c));
      if (-1 < lVar9) {
        return lVar9;
      }
    }
LAB_00021f97:
    lVar9 = -0x7ffffffffffffffd;
  }
  return lVar9;
}

