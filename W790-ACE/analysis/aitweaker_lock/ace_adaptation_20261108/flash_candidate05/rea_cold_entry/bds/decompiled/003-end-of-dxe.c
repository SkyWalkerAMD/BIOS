
void Candidate_ACE1904_end_of_dxe(undefined8 param_1)

{
  longlong lVar1;
  undefined8 local_res8;
  longlong local_res10 [3];
  
  FUN_00009c48(param_1,0x3051005);
  lVar1 = (**(code **)(DAT_0001ff30 + 0x140))(&DAT_0001a920,0,local_res10);
  if (-1 < lVar1) {
    (**(code **)(local_res10[0] + 8))(local_res10[0],0);
  }
  lVar1 = (**(code **)(DAT_0001ff30 + 0x170))(0x200,8,FUN_00001928,0,&DAT_0001a810,&local_res8);
  if (-1 < lVar1) {
    (**(code **)(DAT_0001ff30 + 0x68))(local_res8);
    (**(code **)(DAT_0001ff30 + 0x70))(local_res8);
  }
  FUN_000018e0(&DAT_0001a480);
  lVar1 = (**(code **)(DAT_0001ff30 + 0x138))(2,&DAT_0001a5c0,0,&DAT_0001ff10,&DAT_0001ff08);
  if (lVar1 < 0) {
    DAT_0001ff08 = 0;
    DAT_0001ff10 = 0;
  }
  return;
}

