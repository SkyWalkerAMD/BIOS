
undefined8
Candidate_ACEDxe_CreateEventEx
          (uint param_1,longlong param_2,longlong param_3,undefined8 param_4,longlong *param_5,
          undefined8 *param_6)

{
  undefined8 uVar1;
  
  if (((param_1 & 0x300) != 0) && (((param_2 - 4U & 0xfffffffffffffff3) != 0 || (param_2 == 0xc))))
  {
    return 0x8000000000000002;
  }
  uVar1 = FUN_00009354(param_1,param_2,param_3,param_4,param_5,param_6);
  return uVar1;
}

