
/* WARNING: Type propagation algorithm not settling */

void WS05_788c(void)

{
  char cVar1;
  int iVar2;
  longlong lVar3;
  longlong lVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  bool bVar8;
  bool bVar9;
  bool bVar10;
  undefined8 local_res18;
  longlong local_res20;
  longlong local_68;
  longlong local_60 [3];
  undefined4 local_48;
  undefined4 uStack_44;
  undefined4 uStack_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 uStack_30;
  undefined4 uStack_2c;
  
  local_48 = 0xa3a3b874;
  uStack_44 = 0x41827636;
  uStack_40 = 0x2cf51eba;
  uStack_3c = 0xe3944458;
  local_res20 = 0;
  local_60[1] = 0;
  (**(code **)(DAT_000483d8 + 0x140))(&DAT_0002c5e8,0,&local_68);
  local_res18 = 0x59ab;
  local_38 = local_48;
  uStack_34 = uStack_44;
  uStack_30 = uStack_40;
  uStack_2c = uStack_3c;
  (**(code **)(local_68 + 0x20))
            (u_VARSTORE_OCMR_SETTINGS_NAME_00041870,&local_38,local_60,&local_res18);
  lVar3 = (**(code **)(DAT_000483d8 + 0x40))(4,local_res18,&local_res20);
  if (lVar3 < 0) {
    return;
  }
  lVar4 = (**(code **)(DAT_000483e8 + 0x48))
                    (u_VARSTORE_OCMR_SETTINGS_NAME_00041870,&local_48,0,&local_res18,local_res20);
  lVar3 = local_res20;
  if (lVar4 < 0) {
    return;
  }
  bVar9 = *(char *)(local_60[0] + 0x422) != *(char *)(local_res20 + 0x422);
  bVar7 = true;
  if ((*(char *)(local_60[0] + 0x422) == '\x02') && (*(char *)(local_res20 + 0x422) == '\x02')) {
    if ((*(ushort *)(local_60[0] + 0x423) != 0) && (*(ushort *)(local_res20 + 0x423) != 0)) {
      uVar6 = (*(ushort *)(local_res20 + 0x423) + 0x4f) * 1000;
      iVar2 = *(ushort *)(local_60[0] + 0x423) + 0x4f;
      if (uVar6 < 0x1fbd1) {
        uVar6 = iVar2 * 1000;
        bVar8 = uVar6 < 130000;
        bVar10 = uVar6 == 130000;
LAB_000079e5:
        if (!bVar8 && !bVar10) {
LAB_000079e7:
          bVar9 = true;
        }
      }
      else {
        uVar5 = iVar2 * 1000;
        if (uVar6 < 0x23669) {
          if (130000 < uVar5) {
            bVar8 = uVar5 < 0x23668;
            bVar10 = uVar5 == 0x23668;
            goto LAB_000079e5;
          }
          goto LAB_000079e7;
        }
        if (uVar5 < 0x23669) {
          bVar9 = true;
        }
      }
    }
    if ((*(ushort *)(local_60[0] + 0x425) != 0) && (*(ushort *)(local_res20 + 0x425) != 0)) {
      uVar6 = (*(ushort *)(local_res20 + 0x425) + 0x4f) * 1000;
      iVar2 = *(ushort *)(local_60[0] + 0x425) + 0x4f;
      if (uVar6 < 0x1fbd1) {
        bVar8 = (uint)(iVar2 * 1000) < 130000;
        bVar10 = iVar2 * 1000 == 130000;
LAB_00007a43:
        if (bVar8 || bVar10) goto LAB_00007a49;
      }
      else if (uVar6 < 0x23669) {
        uVar6 = iVar2 * 1000;
        if (130000 < uVar6) {
          bVar8 = uVar6 < 0x23668;
          bVar10 = uVar6 == 0x23668;
          goto LAB_00007a43;
        }
      }
      else if (0x23668 < (uint)(iVar2 * 1000)) goto LAB_00007a49;
      bVar9 = true;
      goto LAB_00007a61;
    }
  }
LAB_00007a49:
  if (!bVar9) {
    cVar1 = FUN_000074cc(local_60[0],local_res20);
    bVar9 = false;
    if (cVar1 != '\0') {
      bVar9 = true;
    }
  }
LAB_00007a61:
  if (*(short *)(local_60[0] + 0x429) != *(short *)(lVar3 + 0x429)) {
    bVar9 = bVar7;
  }
  if (*(short *)(local_60[0] + 0x42b) != *(short *)(lVar3 + 0x42b)) {
    bVar9 = bVar7;
  }
  if (*(short *)(local_60[0] + 0x42d) != *(short *)(lVar3 + 0x42d)) {
    bVar9 = bVar7;
  }
  if (*(short *)(local_60[0] + 0x42f) != *(short *)(lVar3 + 0x42f)) {
    bVar9 = bVar7;
  }
  if ((((*(char *)(DAT_000481b8 + 0x1c) == '\x01') && (*(char *)(local_60[0] + 1) == '\x01')) ||
      ((*(char *)(local_60[0] + 0x9e) == '\0' &&
       (*(char *)(local_60[0] + 1) != *(char *)(lVar3 + 1))))) ||
     ((*(char *)(local_60[0] + 0x9e) != *(char *)(lVar3 + 0x9e) || (bVar9)))) {
    (**(code **)(DAT_000483d8 + 0x80))(local_60 + 1,&DAT_0002c588,0,0);
  }
  return;
}

