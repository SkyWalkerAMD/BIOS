
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00004f98(undefined8 param_1,undefined8 param_2)

{
  byte *pbVar1;
  ulonglong uVar2;
  char cVar3;
  short sVar4;
  ulonglong uVar5;
  longlong lVar6;
  longlong lVar7;
  byte *pbVar8;
  longlong lVar9;
  longlong local_res8;
  ulonglong local_res10;
  byte *local_res18;
  ulonglong local_res20;
  longlong local_58;
  char *local_50;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  
  lVar9 = 0;
  DAT_001801a8 = DAT_0010a920;
  local_58 = 0;
  local_res8 = 0;
  local_res18 = (byte *)0x0;
  FUN_0004a41c(&local_res8,param_2,(ulonglong *)&local_res18);
  if ((local_res8 == 0) || (local_res18 < IMAGE_DOS_HEADER_00000000.e_program + 0x10)) {
    DAT_00180248 = '\0';
  }
  else {
    DAT_00180248 = *(char *)(local_res8 + 0x50);
  }
  FUN_000013d0(&local_res8);
  lVar6 = *(longlong *)(DAT_00180180 + 0x40);
  uVar2 = DAT_001938e8;
  uVar5 = DAT_001938f0;
  if (lVar6 != 0) {
    lVar6 = (**(code **)(lVar6 + 0x18))
                      (lVar6,(longlong)*(int *)(*(longlong *)(lVar6 + 0x48) + 4),&local_res20,
                       &local_res10);
    if (lVar6 < 0) {
      DAT_0010a738 = 0x18;
      _DAT_0010a778 = 0x50;
      uVar2 = 0x50;
      uVar5 = DAT_0010a738;
    }
    else if ((local_res10 < DAT_0010a738) && (local_res20 < _DAT_0010a778)) {
      FUN_000038c8(local_res20);
      DAT_0010a738 = local_res10;
      _DAT_0010a778 = local_res20;
      uVar2 = local_res20;
      uVar5 = local_res10;
    }
    else {
      uVar2 = _DAT_0010a778;
      uVar5 = DAT_0010a738;
      if (((DAT_0010a738 < local_res10) &&
          (uVar2 = _DAT_0010a778, uVar5 = DAT_0010a738, _DAT_0010a778 < local_res20)) &&
         (uVar2 = _DAT_0010a778, uVar5 = DAT_0010a738, DAT_00180248 == '\0')) {
        FUN_00004c3c();
        uVar2 = _DAT_0010a778;
        uVar5 = DAT_0010a738;
      }
    }
  }
  DAT_001938f0 = uVar5;
  DAT_001938e8 = uVar2;
  local_40 = 0xa59a0056;
  local_3c = 0x44b53341;
  local_38 = 0x766d9c9c;
  local_34 = 0x173867f7;
  local_50 = (char *)0x4af964582ebe0275;
  local_48 = 0xf4d3ed91;
  local_44 = 0xaa00b1ed;
  lVar7 = FUN_00009f20(&local_40,(longlong *)&local_50,&local_res8,&local_res18);
  lVar6 = local_res8;
  if (lVar7 < 0) {
    pbVar8 = (byte *)FUN_000484c8(DAT_00193900,4,(short *)0x0);
    lVar6 = lVar9;
    local_res18 = pbVar8;
  }
  else {
    lVar7 = FUN_000b1b20((longlong *)(local_res8 + 0x10),(longlong *)s__SGN__0016bc48,5);
    if ((lVar7 != 0) || (*(byte *)(lVar6 + 0x15) < 2)) goto LAB_00005242;
    pbVar8 = (byte *)FUN_00003a68((byte *)(lVar6 + 0x18));
    cVar3 = *(char *)(lVar6 + 0x18);
    lVar7 = lVar9;
    while (cVar3 != '\0') {
      lVar7 = lVar7 + 1;
      cVar3 = *(char *)(lVar6 + 0x18 + lVar7);
    }
    local_res18 = pbVar8;
    local_58 = FUN_00003a68((byte *)(lVar6 + 0x19 + lVar7));
    lVar6 = local_58;
  }
  if (pbVar8 != (byte *)0x0) {
    sVar4 = *(short *)pbVar8;
    pbVar1 = pbVar8;
    while (sVar4 != 0) {
      pbVar1 = pbVar1 + 2;
      lVar9 = lVar9 + 1;
      sVar4 = *(short *)pbVar1;
    }
    uVar2 = lVar9 * 2 + 0x14;
    local_50 = (char *)FUN_000014c8(uVar2);
    if (local_50 != (char *)0x0) {
      local_res8 = CONCAT44(local_res8._4_4_,DAT_0016ebf8);
      FUN_00009d1c(local_50,uVar2,pbVar8,2);
      FUN_000013d0((longlong *)&local_50);
    }
    FUN_000013d0((longlong *)&local_res18);
  }
  if (lVar6 != 0) {
    FUN_000013d0(&local_58);
  }
LAB_00005242:
  FUN_00003d80();
  if ((((byte)DAT_0018024c & 1) != 0) && (DAT_00180248 != '\0')) {
    DAT_001801a0 = 2;
    if (DAT_001801a8 != 0) {
      (**(code **)(DAT_001801a8 + 8))(DAT_001801a8,1);
    }
    FUN_00003c38(0xffff0001,&LAB_0004b060);
    *(undefined1 *)(DAT_001938d0 + 0x48) = 1;
    if (*(char *)(DAT_001938d0 + 0x49) != '\0') {
      FUN_0000643c();
    }
  }
  if (*(longlong *)(DAT_00180180 + 0x40) != 0) {
    if ((DAT_00180248 == '\0') || (DAT_00180200 == 0)) {
      FUN_00009184();
      FUN_00008d10();
    }
    FUN_00003c38(0xffff0021,FUN_000017b4);
  }
  FUN_00008e94();
  return;
}

