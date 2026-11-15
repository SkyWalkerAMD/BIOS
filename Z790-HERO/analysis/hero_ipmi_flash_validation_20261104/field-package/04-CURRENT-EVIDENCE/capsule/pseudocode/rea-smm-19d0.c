
ulonglong FUN_000019d0(byte *param_1)

{
  longlong *plVar1;
  byte bVar2;
  longlong lVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  undefined8 *local_res8;
  longlong *local_res10;
  longlong local_res18;
  
  DAT_00005228 = 0;
  DAT_00005210 = (undefined8 *)0x0;
  DAT_00005218 = 0;
  if (((*(uint *)(param_1 + 1) & 1) == 0) || (bVar2 = *param_1, (DAT_000051a1 & bVar2) == 0)) {
    if ((*(uint *)(param_1 + 1) & 1) != 0) {
      DAT_00005210 = (undefined8 *)0x0;
      DAT_00005218 = 0;
      DAT_00005228 = 0;
      return 0x8000000000000007;
    }
    bVar2 = *param_1;
    if ((DAT_000051a0 & bVar2) == 0) {
      DAT_00005210 = (undefined8 *)0x0;
      DAT_00005218 = 0;
      DAT_00005228 = 0;
      return 0x8000000000000007;
    }
  }
  if (bVar2 != 1) {
    if ((bVar2 != 2) && (bVar2 != 4)) {
      DAT_00005210 = (undefined8 *)0x0;
      DAT_00005218 = 0;
      DAT_00005228 = 0;
      return 0x8000000000000007;
    }
    DAT_00005210 = DAT_000057b8;
    if (*(longlong *)(param_1 + 5) != 0) {
      if (DAT_00005870 == (undefined8 *)0x0) {
        DAT_00005210 = (undefined8 *)0x0;
        DAT_00005218 = 0;
        DAT_00005228 = 0;
        return 0x8000000000000007;
      }
      lVar3 = (*(code *)*DAT_00005870)(*(longlong *)(param_1 + 5),*(undefined4 *)(param_1 + 0x15));
      if (lVar3 < 0) {
        DAT_00005210 = (undefined8 *)0x0;
        DAT_00005218 = 0;
        DAT_00005228 = 0;
        return 0x8000000000000007;
      }
      if (DAT_00005210 == (undefined8 *)0x0) {
        DAT_00005210 = *(undefined8 **)(param_1 + 5);
      }
      else {
        if (0x2001000 < *(uint *)(param_1 + 0x15)) {
          DAT_00005210 = (undefined8 *)0x0;
          DAT_00005218 = 0;
          DAT_00005228 = 0;
          return 0x8000000000000007;
        }
        FUN_000048f0(DAT_00005210,*(undefined8 **)(param_1 + 5),(ulonglong)*(uint *)(param_1 + 0x15)
                    );
      }
    }
    if (DAT_00005210 == (undefined8 *)0x0) {
      DAT_00005210 = (undefined8 *)0x0;
      DAT_00005218 = 0;
      DAT_00005228 = 0;
      return 0x8000000000000007;
    }
    local_res10 = (longlong *)0x0;
    uVar4 = FUN_000033b8(&DAT_00005210,&local_res10);
    plVar1 = local_res10;
    if ((longlong)uVar4 < 0) {
      if (uVar4 == 0x8000000000000019) {
        if (*param_1 != 2) {
          if (DAT_000051a2 == '\0') {
            DAT_00005210 = (undefined8 *)0x0;
            DAT_00005218 = 0;
            DAT_00005228 = 0;
            return 0x8000000000000019;
          }
          if (DAT_000057b0 == '\0') {
            DAT_00005210 = (undefined8 *)0x0;
            DAT_00005218 = 0;
            DAT_00005228 = 0;
            return 0x8000000000000019;
          }
        }
        uVar4 = 0;
      }
      if ((longlong)uVar4 < 0) {
        DAT_00005210 = (undefined8 *)0x0;
        DAT_00005218 = 0;
        DAT_00005228 = 0;
        return uVar4;
      }
    }
    if (local_res10 == (longlong *)0x0) goto LAB_00001c1a;
    if (*param_1 == 4) {
      uVar4 = 0;
      local_res8 = DAT_00005210;
      local_res18 = 0x1000;
      uVar6 = (ulonglong)
              ((int)local_res10[3] - (uint)*(ushort *)((longlong)local_res10 + 0x1c) >> 0xc);
      if (uVar6 != 0) {
        uVar5 = 0;
        do {
          if ((0x3ffff < uVar5) ||
             (lVar3 = (**(code **)(DAT_00005a40 + 0x10))
                                (DAT_00005a40,&DAT_00005030,1,&local_res8,&local_res18,
                                 (longlong)DAT_000057a8 + uVar5), lVar3 < 0)) break;
          uVar4 = uVar4 + 1;
          local_res8 = (undefined8 *)((longlong)local_res8 + local_res18);
          uVar5 = uVar5 + 0x20;
        } while (uVar4 < uVar6);
      }
      uVar4 = FUN_0000216c(&DAT_000057c0,
                           (undefined8 *)
                           ((ulonglong)*(ushort *)((longlong)plVar1 + 0x1e) + (longlong)plVar1),
                           (longlong)
                           (int)((uint)*(ushort *)((longlong)plVar1 + 0x1c) -
                                (uint)*(ushort *)((longlong)plVar1 + 0x1e)));
      if ((longlong)uVar4 < 0) {
        DAT_00005210 = (undefined8 *)0x0;
        DAT_00005218 = 0;
        DAT_00005228 = 0;
        return uVar4;
      }
      DAT_00005218 = DAT_000057c0;
      DAT_00005228 = *DAT_000057a8;
      goto LAB_00001c1a;
    }
    *(int *)(param_1 + 0x15) = (int)local_res10[3];
    *(undefined8 *)(param_1 + 5) = DAT_000057d8;
    uVar4 = FUN_0000175c(local_res10);
    if ((longlong)uVar4 < 0) goto LAB_00001c1a;
  }
  uVar4 = FUN_00001858((char *)param_1);
LAB_00001c1a:
  if ((longlong)uVar4 < 0) {
    DAT_00005228 = 0;
    DAT_00005218 = 0;
    DAT_00005210 = (undefined8 *)0x0;
    return uVar4;
  }
  return uVar4;
}

