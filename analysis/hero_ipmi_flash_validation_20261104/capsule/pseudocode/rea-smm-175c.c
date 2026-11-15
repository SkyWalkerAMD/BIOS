
undefined8 FUN_0000175c(longlong *param_1)

{
  ulonglong *puVar1;
  longlong lVar2;
  undefined *puVar3;
  undefined8 uVar4;
  
  if (((DAT_000051a0 & 2) == 0) && ((DAT_000051a1 & 2) == 0)) {
    uVar4 = 0x8000000000000003;
  }
  else if ((param_1 == (longlong *)0x0) ||
          (lVar2 = FUN_00004650(param_1,(longlong *)&DAT_000050b0,0x10), puVar1 = DAT_000057d8,
          lVar2 != 0)) {
    uVar4 = 0x8000000000000007;
  }
  else {
    *DAT_000057d8 = (ulonglong)*(uint *)(param_1 + 2);
    puVar1[1] = (ulonglong)param_1;
    puVar1[2] = (ulonglong)(uint)((int)param_1[3] - (int)param_1[2]);
    puVar1[3] = DAT_00005210;
    puVar1[4] = 0;
    puVar1[5] = 0;
    puVar3 = FUN_000015d4();
    (**(code **)(DAT_00005820 + 0x58))(puVar3,&DAT_00005150,0,0,0);
    lVar2 = (**(code **)(DAT_00005820 + 0x58))(puVar3,&DAT_00005150,7,8,&DAT_000057d8);
    uVar4 = 0x8000000000000007;
    if (-1 < lVar2) {
      uVar4 = 0;
    }
  }
  return uVar4;
}

