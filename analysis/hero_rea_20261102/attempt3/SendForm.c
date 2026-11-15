
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong SendForm_from_protocol_table
                   (longlong param_1,undefined4 *param_2,ulonglong param_3,undefined8 param_4,
                   undefined8 param_5,undefined8 param_6,undefined8 *param_7)

{
  undefined8 *puVar1;
  bool bVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined1 uVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong *puVar9;
  undefined4 *puVar10;
  longlong unaff_RBX;
  ulonglong uVar11;
  ulonglong local_res10;
  int local_58;
  undefined4 local_54;
  longlong local_50;
  undefined8 local_48;
  longlong local_40;
  ulonglong local_38;
  ulonglong local_30;
  
  uVar11 = 0;
  local_58 = 0;
  local_res10 = local_res10 & 0xffffffff00000000;
  local_40 = 0;
  local_50 = 0;
  local_48 = 0;
  local_54 = 0;
  puVar10 = param_2;
  FUN_00005484();
  if ((param_2 != (undefined4 *)0x0) && (param_3 != 0)) {
    if ((DAT_0018f048 != 0) || (bVar2 = true, DAT_001801fa != '\0')) {
      lVar6 = FUN_0002b8b4();
      if (lVar6 < 0) {
LAB_0002ab3a:
        lVar6 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0010a408,0,&local_40);
        if (lVar6 != 0) {
          return unaff_RBX;
        }
        (**(code **)(local_40 + 0x20))
                  (u_SendForm_Unsupported_0016d268,u_SendForm_Not_suppored_Nestedly_o_0016d1f0,1,0);
        return unaff_RBX;
      }
      lVar6 = FUN_00013448(param_1);
      if (lVar6 < 0) {
        do {
          local_res10 = DAT_00193738;
          if (DAT_00193738 != 0) {
            DAT_00193738 = *(ulonglong *)(DAT_00193738 + 0x191);
          }
          FUN_000013d0((longlong *)&local_res10);
        } while (local_res10 != 0);
        goto LAB_0002ab3a;
      }
      FUN_00018bd4();
      FUN_00019bb4();
      FUN_0004b018();
      bVar2 = false;
    }
    if (DAT_001938e0 == 0) {
      lVar6 = FUN_00013448(param_1);
      if (lVar6 < 0) {
        return unaff_RBX;
      }
      FUN_00018bd4();
      FUN_00019bb4();
    }
    if (DAT_001801a8 == (undefined8 *)0x0) {
      FUN_00004f98(param_1,puVar10);
    }
    DAT_00193728 = FUN_000014c8(param_3 << 3);
    DAT_00193730 = 0;
    DAT_0018f0e8 = param_4;
    if (param_3 != 0) {
      do {
        puVar9 = *(ulonglong **)(param_2 + uVar11 * 2);
        local_38 = 0;
        local_30 = FUN_00031e04(puVar9,puVar10,&local_38);
        if (local_30 != 0) {
          puVar10 = *(undefined4 **)(param_2 + uVar11 * 2);
          *(undefined4 **)(DAT_00193728 + DAT_00193730 * 8) = puVar10;
          puVar9 = &local_30;
          FUN_000013d0((longlong *)puVar9);
          DAT_00193730 = DAT_00193730 + 1;
        }
        uVar11 = uVar11 + 1;
      } while (uVar11 < param_3);
      if (DAT_00193730 != 0) {
        DAT_00193720 = 0;
        if (DAT_001801c0 == 0) {
          FUN_0001a32c();
          puVar10 = (undefined4 *)0x0;
          FUN_0001a3e4(puVar9,0);
        }
        (**(code **)(DAT_00180188 + 0x18))(0x1f);
        (**(code **)(DAT_00180188 + 0x20))(4);
        FUN_0000b554();
        FUN_0003ce38();
        if (DAT_001801a8 != (undefined8 *)0x0) {
          puVar10 = &local_54;
          (*(code *)*DAT_001801a8)(DAT_001801a8,puVar10,0,0);
        }
        if ((DAT_00180180 != 0) &&
           (puVar1 = *(undefined8 **)(DAT_00180180 + 0x30), puVar1 != (undefined8 *)0x0)) {
          puVar10 = (undefined4 *)0x0;
          (*(code *)*puVar1)(puVar1);
        }
        uVar5 = DAT_001801c9;
        if (DAT_001801e8 != 0) {
          FUN_0000b528(&DAT_001801e8);
        }
        uVar4 = _DAT_0010a778;
        uVar3 = DAT_0010a738;
        DAT_0018f121 = 0;
        if (DAT_00180200 != 0) {
          local_58 = *(int *)(*(longlong *)(DAT_00180200 + 0x18) + 4);
        }
        if ((DAT_00180180 != 0) && (*(longlong *)(DAT_00180180 + 0x40) != 0)) {
          local_res10 = CONCAT44(local_res10._4_4_,
                                 *(undefined4 *)
                                  (*(longlong *)(*(longlong *)(DAT_00180180 + 0x40) + 0x48) + 4));
        }
        FUN_0000205c();
        lVar6 = DAT_001938c0;
        if (bVar2) {
          DAT_001938c0 = 0;
          local_50 = lVar6;
          local_48 = DAT_001801a0;
          if (DAT_0018029e != '\0') {
            FUN_0000b528((longlong *)(DAT_00193800 + 0x28));
          }
        }
        uVar7 = FUN_000014c8(0xb71b04);
        uVar11 = 0xb71b04;
        local_30 = uVar7;
        uVar8 = FUN_000014c8(0xb71b04);
        local_38 = uVar8;
        if ((uVar7 != 0) && (puVar10 = DAT_001938f8, DAT_001938f8 != (undefined4 *)0x0)) {
          uVar11 = uVar7;
          (**(code **)(DAT_00180188 + 0x160))(uVar7,DAT_001938f8,0xb71b04);
        }
        if ((uVar8 != 0) && (puVar10 = DAT_00193908, DAT_00193908 != (undefined4 *)0x0)) {
          uVar11 = uVar8;
          (**(code **)(DAT_00180188 + 0x160))(uVar8,DAT_00193908,0xb71b04);
        }
        FUN_00007348();
        DAT_001801fa = 1;
        FUN_00008920();
        FUN_000b49dc(uVar11,(ulonglong)puVar10);
        DAT_001801fa = '\0';
        DAT_0010a738 = uVar3;
        _DAT_0010a778 = uVar4;
        if (((DAT_00180180 != 0) && (lVar6 = *(longlong *)(DAT_00180180 + 0x40), lVar6 != 0)) &&
           ((int)local_res10 != *(int *)(*(longlong *)(lVar6 + 0x48) + 4))) {
          (**(code **)(lVar6 + 0x20))(lVar6,local_res10 & 0xffffffff);
        }
        if ((uVar7 != 0) && (DAT_001938f8 != (undefined4 *)0x0)) {
          (**(code **)(DAT_00180188 + 0x160))(DAT_001938f8,uVar7);
          FUN_000013d0((longlong *)&local_30);
        }
        if ((uVar8 != 0) && (DAT_00193908 != (undefined4 *)0x0)) {
          FUN_0010749e(DAT_00193908,0xb71b04,0);
          FUN_000013d0((longlong *)&local_38);
        }
        if ((DAT_00180200 != 0) && (local_58 != *(int *)(*(longlong *)(DAT_00180200 + 0x18) + 4))) {
          (**(code **)(DAT_00180200 + 8))(DAT_00180200);
        }
        if (bVar2) {
          if (local_50 != 0) {
            DAT_001938c0 = local_50;
          }
          DAT_001801a0 = local_48;
          if (DAT_0018029e != '\0') {
            FUN_0001799c();
          }
          if (DAT_001801a8 != (undefined8 *)0x0) {
            (*(code *)DAT_001801a8[1])(DAT_001801a8,local_54);
          }
        }
        FUN_00002110();
        if ((!bVar2) && (DAT_001938c0 != 0)) {
          FUN_000013d0(&DAT_001938c0);
        }
        DAT_001801c9 = uVar5;
        FUN_0002c744();
        goto LAB_0002af4e;
      }
    }
    FUN_000013d0(&DAT_00193728);
  }
LAB_0002af4e:
  if (DAT_0018f045 != '\0') {
    if (DAT_00193738 == 0) {
      FUN_00003c38(0xffff001e,FUN_000017b4);
      (**(code **)(DAT_00180198 + 0x68))(0,0,0,0);
    }
    else {
      *(undefined8 *)(DAT_00193738 + 0x191) = *(undefined8 *)(DAT_00193738 + 0x191);
    }
  }
  if (DAT_0018f120 != '\0') {
    if (param_7 != (undefined8 *)0x0) {
      *param_7 = 1;
    }
    DAT_0018f120 = '\0';
  }
  if (DAT_0018f1d8 != '\0') {
    FUN_0003905c();
  }
  DAT_0018f1d8 = 0;
  FUN_0001a32c();
  FUN_000013d0(&DAT_00193728);
  DAT_00193728 = 0;
  DAT_00193730 = 0;
  DAT_00193720 = 0;
  lVar6 = FUN_0002bd74();
  if (lVar6 == 0) {
    FUN_0004af68();
  }
  return unaff_RBX;
}

