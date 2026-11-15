
void FUN_000004a0(longlong param_1,longlong param_2)

{
  byte *pbVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  byte bVar5;
  uint local_res8 [2];
  longlong local_res10;
  
  local_res8[0] = 0xffffffff;
  pbVar1 = (byte *)(param_2 + 0x28);
  FUN_00000424((byte *)(param_2 + 0x108),local_res8);
  FUN_00015b68(param_2 + 0x1e0,0xc4,(uint *)(param_2 + 0x2a4),local_res8,'\0');
  uVar4 = 0;
  if (*(char *)(param_2 + 0x2a0) != '\0') {
    do {
      lVar3 = uVar4 * 0x90;
      FUN_00015b68(param_2 + 0x2a8 + lVar3,4,(uint *)(param_2 + 0x2ac + lVar3),local_res8,'\0');
      FUN_00015b68(param_2 + 0x2b0 + lVar3,0x24,(uint *)(param_2 + 0x2d4 + lVar3),local_res8,'\0');
      bVar5 = (char)uVar4 + 1;
      uVar4 = (ulonglong)bVar5;
    } while (bVar5 < *(byte *)(param_2 + 0x2a0));
  }
  FUN_00015b68(param_2 + 0x360,0x48,(uint *)(param_2 + 0x3a8),local_res8,'\0');
  uVar4 = 0;
  if (*(short *)(param_2 + 0x3a0) != 0) {
    do {
      bVar5 = 0;
      lVar3 = uVar4 * 0x100;
      FUN_00015b68(param_2 + 0x3b0 + lVar3,0x24,(uint *)(param_2 + 0x3d4 + lVar3),local_res8,'\0');
      if (pbVar1[lVar3 + 0x3a8] != 0) {
        do {
          lVar2 = lVar3 + (ulonglong)bVar5 * 0x18;
          FUN_00015b68(param_2 + 0x3d8 + lVar2,4,(uint *)(param_2 + 0x3dc + lVar2),local_res8,'\0');
          bVar5 = bVar5 + 1;
        } while (bVar5 < pbVar1[lVar3 + 0x3a8]);
      }
      bVar5 = 0;
      if (pbVar1[lVar3 + 0x3a9] != 0) {
        do {
          lVar2 = ((ulonglong)bVar5 + uVar4 * 4) * 0x40;
          FUN_00015b68(param_2 + 0x420 + lVar2,0x2c,(uint *)(param_2 + 0x44c + lVar2),local_res8,
                       '\0');
          bVar5 = bVar5 + 1;
        } while (bVar5 < pbVar1[lVar3 + 0x3a9]);
      }
      bVar5 = (char)uVar4 + 1;
      uVar4 = (ulonglong)bVar5;
    } while ((ushort)bVar5 < *(ushort *)(param_2 + 0x3a0));
  }
  uVar4 = 0;
  if (*(char *)(param_2 + 0x3a2) != '\0') {
    do {
      FUN_00015b68(param_2 + 0x1fb0 + uVar4 * 0x40,0x2c,(uint *)(param_2 + 0x1fdc + uVar4 * 0x40),
                   local_res8,'\0');
      bVar5 = (char)uVar4 + 1;
      uVar4 = (ulonglong)bVar5;
    } while (bVar5 < *(byte *)(param_2 + 0x3a2));
  }
  FUN_00015b68(param_2 + 0x2090,4,(uint *)(param_2 + 0x2094),local_res8,'\0');
  uVar4 = 0;
  if (*pbVar1 != 0) {
    do {
      lVar2 = uVar4 * 0x80;
      lVar3 = *(longlong *)(param_2 + 0x20e8) + lVar2;
      FUN_00015b68(lVar3,0x10,(uint *)(lVar3 + 0x10),local_res8,'\0');
      lVar3 = 2;
      do {
        FUN_00015b68(*(longlong *)(param_2 + 0x20e8) + 0x18 + lVar2,0x10,
                     (uint *)(*(longlong *)(param_2 + 0x20e8) + 0x28 + lVar2),local_res8,'\0');
        lVar2 = lVar2 + 0x28;
        lVar3 = lVar3 + -1;
      } while (lVar3 != 0);
      bVar5 = (char)uVar4 + 1;
      uVar4 = (ulonglong)bVar5;
    } while (bVar5 < *pbVar1);
  }
  if (param_1 == 0) {
    lVar3 = -0x7ffffffffffffffe;
  }
  else {
    lVar3 = FUN_000160cc(param_1,(int *)(param_2 + 0xf8),&local_res10);
  }
  if (-1 < lVar3) {
    FUN_00015b68(local_res10,(ulonglong)*(uint *)(param_2 + 0x100),(uint *)(param_2 + 0xf4),
                 local_res8,'\0');
    (**(code **)(DAT_00018a28 + 0x48))(local_res10);
  }
  FUN_00015b68((longlong)pbVar1,200,(uint *)(param_2 + 0xf0),local_res8,'\x01');
  *(uint *)(param_2 + 0x1c) = local_res8[0];
  return;
}

