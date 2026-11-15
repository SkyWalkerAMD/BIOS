
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_000b49dc(ulonglong param_1,ulonglong param_2)

{
  uint uVar1;
  uint uVar2;
  bool bVar3;
  longlong lVar4;
  longlong lVar5;
  longlong *plVar6;
  undefined4 *puVar7;
  undefined *puVar8;
  undefined4 *puVar9;
  undefined8 *puVar10;
  undefined8 *puVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  ulonglong local_res8;
  ulonglong local_res10;
  undefined4 local_res18 [2];
  undefined8 *local_res20;
  undefined4 uVar14;
  longlong local_68;
  longlong local_60 [3];
  undefined1 local_48 [16];
  
  puVar11 = (undefined8 *)0x0;
  local_60[1] = 0;
  puVar8 = (undefined *)0x2;
  local_res20 = (undefined8 *)0x0;
  bVar3 = false;
  local_68 = 0;
  local_res8 = param_1;
  local_res10 = param_2;
  lVar5 = (**(code **)(DAT_00180188 + 0x138))(2,&DAT_0010a378,0,&local_res20,&local_68);
  puVar10 = puVar11;
  if (local_res20 != (undefined8 *)0x0) {
    do {
      puVar8 = *(undefined **)(local_68 + (longlong)puVar10 * 8);
      lVar5 = (**(code **)(DAT_00180188 + 0x98))(puVar8,&DAT_0010a568);
      if (-1 < lVar5) {
        puVar8 = *(undefined **)(local_68 + (longlong)puVar10 * 8);
        lVar5 = (**(code **)(DAT_00180188 + 0x98))(puVar8,&DAT_0010a378);
        break;
      }
      puVar10 = (undefined8 *)((longlong)puVar10 + 1);
    } while (puVar10 < local_res20);
  }
  if ((lVar5 < 0) || (DAT_001807b8 == 0)) {
    puVar8 = &DAT_0010a378;
    lVar5 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0010a378,0);
    if (lVar5 < 0) {
      return -0x7ffffffffffffff2;
    }
  }
  FUN_000b467c((longlong)puVar8);
  lVar4 = DAT_001807b8;
  lVar5 = *(longlong *)(*(longlong *)(DAT_001807b8 + 0x18) + 8);
  uVar1 = *(uint *)(lVar5 + 4);
  uVar2 = *(uint *)(lVar5 + 8);
  if ((uVar1 != 0x400) || (uVar2 != 0x300)) {
    DAT_0013c25c = (float)uVar2 / _DAT_0017f8cc;
    DAT_0013c260 = (float)uVar1 * DAT_0017f74c;
  }
  DAT_001807b0 = uVar1;
  DAT_001807b4 = uVar2;
  plVar6 = (longlong *)FUN_0007fbc8();
  lVar5 = 0x100;
  *plVar6 = lVar4;
  puVar9 = (undefined4 *)((longlong)plVar6 + 0x414);
  *(undefined1 *)(plVar6 + 2) = 0;
  plVar6[0x104] = 0;
  do {
    puVar9[-0x100] = 0xffffffff;
    *puVar9 = 0xffffffff;
    puVar9 = puVar9 + 1;
    lVar5 = lVar5 + -1;
  } while (lVar5 != 0);
  plVar6[1] = 0;
  *(uint *)((longlong)plVar6 + 0x814) = uVar1;
  *(uint *)(plVar6 + 0x103) = uVar2;
  plVar6 = local_60 + 2;
  lVar5 = (**(code **)(DAT_00180188 + 0x50))(0x200,8,FUN_000b4950,0,plVar6);
  uVar14 = (undefined4)((ulonglong)plVar6 >> 0x20);
  if ((-1 < lVar5) &&
     (lVar5 = (**(code **)(DAT_00180188 + 0xa8))(&DAT_0010a378,local_60[2],local_48), -1 < lVar5)) {
    lVar5 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0013c278,0,&DAT_00190c70);
    if (lVar5 == -0x7ffffffffffffff2) {
      DAT_00190c70 = 0;
    }
    else {
      (**(code **)(DAT_00190c70 + 0x10))
                (DAT_00190c70,0,0,DAT_001807b0,CONCAT44(uVar14,DAT_001807b4));
      (**(code **)(DAT_00190c70 + 0x40))(DAT_00190c70,3);
      if (-1 < lVar5) {
        (**(code **)(DAT_00190c70 + 0x80))(DAT_00190c70,2);
        puVar10 = (undefined8 *)FUN_00051024(0x40);
        if (puVar10 != (undefined8 *)0x0) {
          *puVar10 = &PTR_FUN_00177668;
          puVar11 = puVar10;
        }
        lVar5 = DAT_00190c70;
        local_res10 = local_res10 & 0xffffffff00000000;
        local_res8 = local_res8 & 0xffffffff00000000;
        local_res18[0] = 0;
        if (DAT_00190c70 != 0) {
          *(uint *)((longlong)puVar11 + 0x34) = DAT_001807b0;
          *(uint *)(puVar11 + 7) = DAT_001807b4;
          puVar11[1] = lVar5;
          (**(code **)(lVar5 + 8))(lVar5);
          (**(code **)(puVar11[1] + 0x30))(puVar11[1],&local_res10,&local_res8,local_res18);
          *(undefined4 *)((longlong)puVar11 + 0x2c) = (undefined4)local_res10;
          *(undefined4 *)(puVar11 + 6) = (undefined4)local_res8;
          (**(code **)(puVar11[1] + 0x48))(puVar11[1],puVar11 + 2);
        }
        lVar5 = FUN_0007e810();
        puVar8 = &DAT_0010a6f8;
        *(undefined8 **)(lVar5 + 0x348) = puVar11;
        lVar5 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0010a6f8,0,local_60);
        if (-1 < lVar5) {
          puVar8 = &DAT_0013c268;
          lVar5 = (**(code **)(local_60[0] + 0x80))();
          if (-1 < lVar5) {
            bVar3 = true;
          }
        }
        FUN_000b4e5c((ulonglong)puVar8);
        if (bVar3) {
          (**(code **)(local_60[0] + 0x90))(&DAT_0013c268);
        }
        plVar6 = (longlong *)FUN_0007fbc8();
        lVar5 = *(longlong *)(*(longlong *)(*plVar6 + 0x18) + 8);
        uVar13 = (ulonglong)*(uint *)(lVar5 + 8);
        uVar12 = (ulonglong)*(uint *)(lVar5 + 4);
        puVar9 = (undefined4 *)(uVar13 * uVar12 * 4);
        puVar7 = FUN_00051024((ulonglong)puVar9);
        if (puVar7 != (undefined4 *)0x0) {
          (**(code **)(*plVar6 + 0x10))(*plVar6,puVar7,2,0,0,0,0,uVar12,uVar13,uVar12 << 2);
          (**(code **)(DAT_00180188 + 0x48))();
          puVar9 = puVar7;
        }
        FUN_000b5514();
        FUN_0008835c(puVar9);
        if (DAT_00190b29 != '\0') {
          FUN_00001150(0);
          DAT_00190b29 = '\0';
        }
        if (DAT_0018f045 != '\0') {
          FUN_00003c38(0xffff001e,FUN_000017b4);
          local_res10 = 0;
          lVar5 = (**(code **)(DAT_00180188 + 0x140))(&DAT_0010a698,0,&local_res10);
          if (-1 < lVar5) {
            (**(code **)(DAT_00180198 + 0x68))(0,0,0,0);
          }
          (**(code **)(DAT_00180198 + 0x68))(1,0,0,0);
        }
        return 0;
      }
    }
    lVar5 = -0x7ffffffffffffff2;
  }
  return lVar5;
}

