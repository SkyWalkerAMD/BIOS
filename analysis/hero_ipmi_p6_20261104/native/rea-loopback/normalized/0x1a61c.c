longlong FUN_0001a61c(void)
{
  longlong lVar1;
  int *piVar2;
  longlong lVar3;
  longlong lVar4;
  longlong lVar5;
  longlong local_res8;
  ulonglong local_res10;
  int *local_res18;
  lVar4 = 0;
  local_res8 = 0;
  lVar1 = FUN_00015b1c();
  if (lVar1 == -0x7ffffffffffffffd) {
    lVar1 = FUN_000338c8(&DAT_00180210,0x20);
    if (lVar1 < 0) {
      return lVar1;
    }
    lVar1 = FUN_000338c8(&DAT_001801f0,0x10);
    if (lVar1 < 0) {
      return lVar1;
    }
  }
  if (*(longlong *)(DAT_001801f0 + 0x70) != 0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x70));
  }
  if (*(longlong *)(DAT_001801f0 + 0x170) != 0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x170));
  }
  if (*(longlong *)(DAT_001801f0 + 0x80) != 0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x80));
  }
  lVar5 = 0x70;
  *(undefined8 *)(DAT_001801f0 + 0x170) = 0;
  lVar3 = 0x70;
  do {
    *(undefined8 *)(lVar3 + DAT_001801f0) = 0;
    lVar3 = lVar3 + 0x10;
  } while (lVar3 < 0x90);
  *(undefined8 *)(DAT_001801f0 + 0x178) = 0;
  lVar3 = lVar4;
  do {
    *(undefined8 *)(lVar3 + 0x78 + DAT_001801f0) = 0;
    lVar3 = lVar3 + 0x10;
  } while (lVar3 < 0x20);
  if (*(longlong *)(DAT_00180210 + 0x70) != 0) {
    FUN_000013d0((longlong *)(DAT_00180210 + 0x70));
  }
  if (*(longlong *)(DAT_00180210 + 0x170) != 0) {
    FUN_000013d0((longlong *)(DAT_00180210 + 0x170));
  }
  if (*(longlong *)(DAT_00180210 + 0x80) != 0) {
    FUN_000013d0((longlong *)(DAT_00180210 + 0x80));
  }
  *(undefined8 *)(DAT_00180210 + 0x170) = 0;
  do {
    *(undefined8 *)(lVar5 + DAT_00180210) = 0;
    lVar5 = lVar5 + 0x10;
  } while (lVar5 < 0x90);
  *(undefined8 *)(DAT_00180210 + 0x178) = 0;
  do {
    *(undefined8 *)(lVar4 + 0x78 + DAT_00180210) = 0;
    lVar4 = lVar4 + 0x10;
  } while (lVar4 < 0x20);
  DAT_00193788 = FUN_0001a908(1,&DAT_0018f098);
  local_res8 = 0;
  lVar4 = FUN_0000130c(u_DefaultBootOrder_0016c750,&DAT_0010a740,(undefined4 *)0x0,&local_res8);
  if (lVar4 != 0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x70));
    *(longlong *)(DAT_001801f0 + 0x70) = lVar4;
    *(longlong *)(DAT_001801f0 + 0x78) = local_res8;
  }
  local_res8 = 0;
  lVar4 = FUN_0000130c(u_DefaultDriverOrder_0016c778,&DAT_0010a750,(undefined4 *)0x0,&local_res8);
  if (lVar4 != 0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x170));
    *(longlong *)(DAT_001801f0 + 0x170) = lVar4;
    *(longlong *)(DAT_001801f0 + 0x178) = local_res8;
  }
  local_res10 = 0;
  piVar2 = (int *)FUN_0000130c(u_DefaultLegacyDevOrder_0016c7a0,&DAT_0010a768,(undefined4 *)0x0,
                               (longlong *)&local_res10);
  local_res18 = piVar2;
  if (piVar2 != (int *)0x0) {
    FUN_000013d0((longlong *)(DAT_001801f0 + 0x80));
    lVar4 = FUN_0001b954(piVar2,local_res10);
    *(longlong *)(DAT_001801f0 + 0x80) = lVar4;
    local_res10 = -(ulonglong)(*(longlong *)(DAT_001801f0 + 0x80) != 0) & local_res10;
    *(ulonglong *)(DAT_001801f0 + 0x88) = local_res10;
    FUN_000013d0((longlong *)&local_res18);
  }
  FUN_00003c38(0xffff0018,FUN_000017b4);
  return lVar1;
}
