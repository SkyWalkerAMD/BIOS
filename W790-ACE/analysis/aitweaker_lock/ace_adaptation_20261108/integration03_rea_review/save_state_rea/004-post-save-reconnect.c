
undefined8 Candidate_ACE_PostSaveReconnect(longlong param_1,undefined8 param_2,undefined8 *param_3)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 local_res8 [4];
  
  if (DAT_000828a0 != (longlong *)0x0) {
    lVar2 = 0;
    if (*DAT_000828a0 != 0) {
      param_1 = 0;
      do {
        param_2 = *(undefined8 *)(param_1 + (longlong)DAT_000828a0);
        param_3 = local_res8;
        lVar1 = (**(code **)(DAT_000825d8 + 0x50))(DAT_000825d8);
        if (-1 < lVar1) {
          param_3 = (undefined8 *)0x0;
          param_2 = 0;
          lVar1 = (**(code **)(DAT_000824c8 + 0x110))(local_res8[0]);
          if (-1 < lVar1) {
            param_3 = (undefined8 *)0x0;
            param_2 = 0;
            (**(code **)(DAT_000824c8 + 0x108))(local_res8[0],0,0,1);
          }
        }
        lVar2 = lVar2 + 1;
        param_1 = lVar2 * 8;
      } while (DAT_000828a0[lVar2] != 0);
    }
    if ((DAT_00082970 != '\0') && (DAT_00082899 == '\0')) {
      DAT_00082899 = 1;
      FUN_00029b34(param_1,param_2,param_3);
      DAT_00082899 = '\0';
    }
  }
  return 0;
}

