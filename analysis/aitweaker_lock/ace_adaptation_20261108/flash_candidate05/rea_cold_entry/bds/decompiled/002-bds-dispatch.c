
/* WARNING: Removing unreachable block (ram,0x000027b4) */
/* WARNING: Removing unreachable block (ram,0x000027bd) */

void Candidate_ACE1904_bds_dispatch(void)

{
  longlong lVar1;
  undefined **ppuVar2;
  undefined8 *puVar3;
  undefined8 local_res10;
  
  puVar3 = (undefined8 *)0x0;
  local_res10 = 0;
  lVar1 = (**(code **)(DAT_0001ff40 + 0x48))(u_Timeout_0001b840,&DAT_0001a310,0,&local_res10,0);
  if (lVar1 == -0x7ffffffffffffff2) {
    (**(code **)(DAT_0001ff40 + 0x58))(u_Timeout_0001b840,&DAT_0001a310,7,2,&DAT_0001bae0);
  }
  lVar1 = (**(code **)(DAT_0001ff30 + 0x138))(0,0,0,&DAT_00020188,&DAT_00020190);
  if (lVar1 < 0) {
    DAT_00020188 = 0;
    DAT_00020190 = 0;
  }
  lVar1 = FUN_00009b68();
  DAT_0001fef4 = *(int *)(lVar1 + 0xc);
  if ((DAT_0001fef4 == 0x12) || (DAT_0001fef8 = 1, DAT_0001fef4 == 0x20)) {
    DAT_0001fef8 = 3;
  }
  lVar1 = (**(code **)(DAT_0001ff30 + 0x140))(&DAT_0001a770,0,0x1ff00);
  if (lVar1 < 0) {
    DAT_0001ff00 = puVar3;
  }
  ppuVar2 = &PTR_FUN_0001b8c0;
  do {
    if (DAT_0001ff00 != (undefined8 *)0x0) {
      (*(code *)*DAT_0001ff00)();
    }
    (*(code *)*ppuVar2)();
    puVar3 = (undefined8 *)((longlong)puVar3 + 1);
    ppuVar2 = &PTR_FUN_0001b8c0 + (longlong)puVar3;
  } while (*ppuVar2 != (undefined *)0x0);
  return;
}

