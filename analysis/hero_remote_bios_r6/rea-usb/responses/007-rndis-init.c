/* {"status": "resolved", "address": "0x39c", "name": "FUN_0000039c"} */

void FUN_0000039c(undefined8 param_1,longlong param_2)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  ulonglong uVar4;
  
  DAT_000023d0 = *(undefined8 *)(param_2 + 0x60);
  DAT_000023c8 = param_2;
  FUN_00001fcc();
  psVar3 = (short *)FUN_00001fcc();
  do {
    if (*psVar3 == -1) {
      psVar3 = (short *)0x0;
LAB_000003f0:
      if (psVar3 == (short *)0x0) {
        uVar4 = FUN_00000360();
        FUN_00000350();
        uVar1 = in(0x1808);
        FUN_00000330();
        while (iVar2 = in(0x1808), (((uVar1 & 0xffffff) + 0x16b) - iVar2 >> 0x17 & 1) == 0) {
          FUN_00000320();
        }
        FUN_00000330();
        if ((uVar4 >> 9 & 1) == 0) {
          FUN_00000350();
        }
        else {
          FUN_00000340();
        }
        return;
      }
      if ((DAT_00002328 == *(longlong *)(psVar3 + 4)) && (DAT_00002330 == *(longlong *)(psVar3 + 8))
         ) {
        return;
      }
    }
    else if (*psVar3 == 4) goto LAB_000003f0;
    psVar3 = (short *)((longlong)psVar3 + (ulonglong)(ushort)psVar3[1]);
  } while( true );
}



/* {"status": "resolved", "address": "0x464", "name": "FUN_00000464"} */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00000464(undefined8 param_1,longlong param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined8 uVar3;
  undefined1 local_res18 [8];
  undefined8 local_res20;
  undefined4 local_df8;
  undefined4 local_df4;
  undefined4 local_df0;
  undefined4 local_dec;
  undefined1 local_de8 [3061];
  char local_1f3;
  
  uVar3 = 0;
  local_df8 = 0xec87d643;
  local_df4 = 0x4bb5eba4;
  local_df0 = 0x3e3fe5a1;
  local_dec = 0xa90db236;
  local_res20 = 0xddb;
  if (DAT_000023e8 == 0) {
    DAT_000023e0 = *(longlong *)(param_2 + 0x58);
    DAT_000023e8 = param_2;
  }
  lVar1 = (**(code **)(DAT_000023e0 + 0x48))
                    (u_Setup_00002350,&local_df8,local_res18,&local_res20,local_de8);
  if ((((-1 < lVar1) && (uVar2 = FUN_00002038(), (int)uVar2 != 0x20)) &&
      (uVar2 = FUN_00002038(), (int)uVar2 != 0x12)) && (uVar3 = 0, local_1f3 == '\x01')) {
    _DAT_00002300 = param_1;
    _DAT_00002308 = param_1;
    uVar3 = (**(code **)(DAT_000023d0 + 0x148))
                      (&DAT_00002308,&DAT_000022c0,&PTR_LAB_000022e0,&DAT_00002280,&PTR_LAB_00002310
                       ,0);
  }
  return uVar3;
}

