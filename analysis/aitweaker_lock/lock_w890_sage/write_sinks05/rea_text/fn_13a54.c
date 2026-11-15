
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00013a54(ushort param_1)

{
  short sVar1;
  char cVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 *puVar6;
  ulonglong uVar7;
  short *psVar8;
  longlong lVar9;
  undefined4 extraout_XMM0_Da;
  undefined4 extraout_XMM0_Da_00;
  undefined4 extraout_XMM0_Da_01;
  undefined4 uVar10;
  char local_res10 [8];
  undefined1 local_res18 [8];
  longlong local_res20;
  undefined8 local_78;
  undefined8 local_70;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined8 local_48;
  undefined4 local_40;
  
  local_48 = 0;
  local_40 = 0;
  local_78 = 1;
  local_res20 = 0;
  local_70 = 0;
  local_58 = 0;
  uStack_50 = 0;
  local_res10[0] = '\0';
  (**(code **)(DAT_000483e8 + 0x48))
            (u_MaskBuild_000429b0,&DAT_00030030,local_res18,&local_78,local_res10);
  local_68 = 0xec87d643;
  local_64 = 0x4bb5eba4;
  local_60 = 0x3e3fe5a1;
  local_5c = 0xa90db236;
  (**(code **)(DAT_00048290 + 0x20))(u_Setup_00041658,&local_68,&local_res20,&local_70);
  _DAT_00049e68 = 0;
  _DAT_00049e6a = (undefined2)DAT_00048288[3];
  _DAT_00049e70 = DAT_00048280;
  _DAT_00049e78 = *(undefined2 *)((longlong)DAT_00048288 + 0x1a);
  cVar2 = (**(code **)(DAT_00048290 + 0x18))(&DAT_00049e68,3,0);
  if (cVar2 == '\0') {
    lVar9 = ((ulonglong)param_1 + 0x2e) * 0x10 + *DAT_00048288;
    lVar3 = FUN_0001e280(extraout_XMM0_Da,0x10);
    lVar4 = FUN_0001e280(extraout_XMM0_Da_00,0x10);
    lVar5 = FUN_0001e280(extraout_XMM0_Da_01,0x10);
    uVar10 = FUN_00011504(lVar9,lVar3,lVar4,lVar5);
    puVar6 = (undefined8 *)FUN_0001e280(uVar10,0x10);
    if (puVar6 != (undefined8 *)0x0) {
      FUN_00013254(lVar9,*(undefined8 *)(lVar9 + 8),puVar6,puVar6 + 1);
      uVar10 = (**(code **)(DAT_00048290 + 8))(param_1 + 0x2e,*puVar6,puVar6[1]);
      uVar7 = 0;
      if (local_res10[0] == '\0') {
        puVar6 = (undefined8 *)FUN_0001e280(uVar10,0x10);
        if (puVar6 == (undefined8 *)0x0) {
          return;
        }
        FUN_00013254(lVar3,*(undefined8 *)(lVar3 + 8),puVar6,puVar6 + 1);
        uVar10 = (**(code **)(DAT_000483e8 + 0x58))
                           (u_ProfileMask1_00042a80,&DAT_00030030,7,puVar6[1],*puVar6);
        puVar6 = (undefined8 *)FUN_0001e280(uVar10,0x10);
        if (puVar6 == (undefined8 *)0x0) {
          return;
        }
        FUN_00013254(lVar4,*(undefined8 *)(lVar4 + 8),puVar6,puVar6 + 1);
        uVar10 = (**(code **)(DAT_000483e8 + 0x58))
                           (u_ProfileMask2_00042aa0,&DAT_00030030,7,puVar6[1],*puVar6);
        puVar6 = (undefined8 *)FUN_0001e280(uVar10,0x10);
        if (puVar6 == (undefined8 *)0x0) {
          return;
        }
        FUN_00013254(lVar5,*(undefined8 *)(lVar5 + 8),puVar6,puVar6 + 1);
        (**(code **)(DAT_000483e8 + 0x58))
                  (u_ProfileMask3_00042ac0,&DAT_00030030,7,puVar6[1],*puVar6);
        local_res10[0] = '\x01';
        (**(code **)(DAT_000483e8 + 0x58))
                  (u_MaskBuild_000429b0,&DAT_00030030,7,local_78,local_res10);
      }
      FUN_0001e3ac(&local_58,0x1c,u_ProfileName_d_000429d0,(uint)param_1);
      psVar8 = (short *)(local_res20 + 0x157);
      if (psVar8 != (short *)0x0) {
        sVar1 = *psVar8;
        while (sVar1 != 0) {
          if (0xc < uVar7) goto LAB_00013d31;
          uVar7 = uVar7 + 1;
          sVar1 = psVar8[uVar7];
        }
        if (uVar7 != 0) {
LAB_00013d31:
          (**(code **)(DAT_000483e8 + 0x58))(&local_58,&DAT_00030030,7,0x1c,psVar8);
          FUN_00001060(local_res20 + 0x157,0x1c);
          FUN_000125d0(DAT_00048280);
          return;
        }
      }
      _DAT_0004b168 = 0x1800;
      _DAT_0004b16a = (undefined2)DAT_00048288[3];
      _DAT_0004b170 = DAT_00048280;
      _DAT_0004b178 = 0x5b1;
      (**(code **)(DAT_00048290 + 0x18))(&DAT_0004b168,1,0);
    }
  }
  return;
}

