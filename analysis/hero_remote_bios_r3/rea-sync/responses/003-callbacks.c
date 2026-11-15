
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00001fcc(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  undefined1 *puVar2;
  undefined8 **ppuVar3;
  undefined1 uVar4;
  undefined8 uVar5;
  undefined8 *local_res8;
  undefined8 *local_res10;
  
  if (DAT_00016990 == 0) {
    DAT_00016980 = *(longlong *)(param_2 + 0x60);
    DAT_00016988 = *(undefined8 *)(param_2 + 0x58);
    DAT_00016990 = param_2;
  }
  ppuVar3 = &local_res8;
  uVar5 = param_1;
  lVar1 = (**(code **)(DAT_00016980 + 0x118))(param_1,&DAT_00014138,ppuVar3,param_1,0,2);
  uVar4 = (undefined1)uVar5;
  if (-1 < lVar1) {
    ppuVar3 = &local_res10;
    lVar1 = (**(code **)(DAT_00016980 + 0x140))(&DAT_00014088,0);
    if (-1 < lVar1) {
      uVar4 = 0xd0;
      ppuVar3 = (undefined8 **)0x0;
      (*(code *)*local_res10)(local_res10,local_res8);
    }
  }
  DAT_00016908 = FUN_00009c78(DAT_000168d0,2,(ulonglong)ppuVar3,uVar4);
  FUN_00009c78(DAT_000168d0,3,(ulonglong)ppuVar3,uVar4);
  FUN_00009c78(DAT_000168d0,4,(ulonglong)ppuVar3,uVar4);
  FUN_00009c78(DAT_000168d0,5,(ulonglong)ppuVar3,uVar4);
  FUN_00009c78(DAT_000168d0,6,(ulonglong)ppuVar3,uVar4);
  _DAT_00016910 = FUN_00009c78(DAT_000168d0,7,(ulonglong)ppuVar3,uVar4);
  DAT_000168b8 = FUN_00009c78(DAT_000168d0,8,(ulonglong)ppuVar3,uVar4);
  DAT_00016880 = FUN_00009c78(DAT_000168d0,9,(ulonglong)ppuVar3,uVar4);
  DAT_000168e0 = FUN_00009c78(DAT_000168d0,10,(ulonglong)ppuVar3,uVar4);
  DAT_000168a8 = FUN_00009c78(DAT_000168d0,0xb,(ulonglong)ppuVar3,uVar4);
  DAT_000168f8 = FUN_00009c78(DAT_000168d0,0xc,(ulonglong)ppuVar3,uVar4);
  FUN_00009c78(DAT_000168d0,0xd,(ulonglong)ppuVar3,uVar4);
  DAT_00016888 = FUN_00009c78(DAT_000168d0,0xe,(ulonglong)ppuVar3,uVar4);
  local_res10 = (undefined8 *)0x0;
  _DAT_00016840 = param_1;
  _DAT_00018280 = param_2;
  puVar2 = (undefined1 *)FUN_000041f4(0x18);
  if (puVar2 != (undefined1 *)0x0) {
    *(undefined8 *)(puVar2 + 0x10) = 0;
    *(undefined1 **)(puVar2 + 8) = &LAB_00001edc;
    *puVar2 = 1;
    (**(code **)(DAT_00016838 + 0x50))(0x200,8,FUN_0000735c,puVar2,&local_res8);
    (**(code **)(DAT_00016838 + 0xa8))(&DAT_00013a10,local_res8,&local_res10);
    (**(code **)(DAT_00016838 + 0x68))(local_res8);
  }
  return 0;
}




/* WARNING: Type propagation algorithm not settling */

void FUN_00001a2c(void)

{
  undefined8 uVar1;
  longlong lVar2;
  ulonglong uVar3;
  longlong local_res18;
  ulonglong local_res20;
  short *local_38;
  longlong local_30 [3];
  
  local_30[2] = 0;
  local_38 = (short *)0x0;
  uVar1 = (**(code **)(DAT_00016980 + 0x18))(0x1f);
  (**(code **)(DAT_00016980 + 0x20))(4);
  FUN_0000ba08();
  local_30[1] = 0;
  local_30[0] = 0;
  local_res20 = 0;
  local_res18 = 0;
  lVar2 = (**(code **)(DAT_00016980 + 0x138))(2,&DAT_00013a10,0,&local_res20,&local_res18);
  if ((-1 < lVar2) && (uVar3 = 0, local_res20 != 0)) {
    do {
      lVar2 = (**(code **)(DAT_00016980 + 0x98))
                        (*(undefined8 *)(local_res18 + uVar3 * 8),&DAT_00013a10,local_30 + 1);
      if ((-1 < lVar2) &&
         ((lVar2 = (**(code **)(DAT_00016980 + 0x98))
                             (*(undefined8 *)(local_res18 + uVar3 * 8),&DAT_00013b50,local_30),
          -1 < lVar2 && (local_30[0] != 0)))) {
        DAT_00016900 = local_30[0];
      }
      uVar3 = (ulonglong)((int)uVar3 + 1);
    } while (uVar3 < local_res20);
  }
  (**(code **)(DAT_00016900 + 8))(DAT_00016900,0,&local_38);
  if (local_38 != (short *)0x0) {
    DAT_000168b0 = FUN_00002c00(local_38);
    (**(code **)(DAT_00016838 + 0x48))(local_38);
  }
  FUN_00000db0();
  FUN_0000ba08();
  if (DAT_000168f0 != 0) {
    (**(code **)(DAT_000168f0 + 0x18))(local_30 + 2);
  }
  (**(code **)(DAT_00016980 + 0x18))(0x1f);
  (**(code **)(DAT_00016980 + 0x20))(uVar1);
  if (DAT_000168b0 != 0) {
    (**(code **)(DAT_00016838 + 0x48))();
    DAT_000168b0 = 0;
  }
  return;
}

