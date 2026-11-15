
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong Candidate_ACE1904_main_initializer(undefined8 *param_1,longlong param_2)

{
  byte bVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined8 local_res8;
  undefined8 *local_res10;
  undefined8 local_res18;
  undefined4 uVar4;
  undefined4 uVar5;
  
  local_res18 = 0;
  uVar4 = 0xc5912ed9;
  uVar5 = 0x1f233699;
  if (DAT_00082a78 == 0) {
    DAT_00082a68 = *(undefined8 *)(param_2 + 0x60);
    DAT_00082a80 = *(undefined8 *)(param_2 + 0x58);
    DAT_00082a70 = param_1;
    DAT_00082a78 = param_2;
  }
  DAT_000824c8 = *(longlong *)(param_2 + 0x60);
  DAT_000824d8 = *(undefined8 *)(param_2 + 0x58);
  DAT_000824c0 = param_2;
  DAT_000824d0 = param_1;
  bVar1 = FUN_000061dc();
  if (bVar1 == 1) {
    lVar2 = -0x7ffffffffffffffd;
  }
  else {
    puVar3 = param_1;
    lVar2 = (**(code **)(DAT_000824c8 + 0x118))
                      (param_1,&DAT_0006ab10,&local_res8,param_1,0,2,uVar4,uVar5);
    if (-1 < lVar2) {
      puVar3 = (undefined8 *)&DAT_0006a6f0;
      lVar2 = (**(code **)(DAT_000824c8 + 0x140))(&DAT_0006a6f0,0,&local_res10);
      if (-1 < lVar2) {
        (*(code *)*local_res10)(local_res10,local_res8,param_1,&DAT_00092b30);
        puVar3 = local_res10;
      }
    }
    _DAT_0006ac38 = _DAT_0007af70;
    uRam000000000006ac40 = uRam000000000007af78;
    FUN_00001304();
    FUN_00006f00(puVar3);
    lVar2 = FUN_00044b58((longlong)puVar3);
    if (lVar2 < 0) {
      lVar2 = FUN_0000122c(lVar2);
    }
    else {
      FUN_0000ebf4();
      FUN_00010144();
      lVar2 = FUN_00010a94(puVar3,0);
      if (-1 < lVar2) {
        FUN_00005ab8(0xffff0005,&LAB_000367e0);
        DAT_00082628 = 0;
        FUN_000092c0();
        Candidate_ACE1904_protocol_installer();
        lVar2 = Candidate_ACE1904_post_publication_initializer();
        if (lVar2 < 0) {
          (**(code **)(DAT_000824c8 + 0x150))
                    (&DAT_00082610,&DAT_0006a780,&PTR_Candidate_ACE1904_boot_manager_0006ab40,0);
          FUN_00020ee4(DAT_00082610);
          local_res8 = DAT_00082610;
          (**(code **)(DAT_000824c8 + 0x150))(&local_res8,&DAT_0006a3d0,&PTR_DAT_0006ab20,0);
          FUN_0000447c(DAT_00082610);
        }
      }
    }
  }
  return lVar2;
}

