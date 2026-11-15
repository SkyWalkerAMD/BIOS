
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001140(undefined8 param_1,longlong param_2)

{
  DAT_000020a8 = *(undefined8 *)(param_2 + 0x58);
  DAT_000020a0 = *(longlong *)(param_2 + 0x60);
  _DAT_00002098 = param_2;
  DAT_000020b0 = DAT_000020a8;
  DAT_000020c8 = DAT_000020a0;
  (**(code **)(DAT_000020a0 + 0x50))(0x201,8,&LAB_00001428,0,&DAT_000020b8);
  (**(code **)(DAT_000020c8 + 0x50))(0x60000202,8,FUN_00001434,0,&DAT_000020c0);
  _DAT_00002100 = DAT_000020a8;
  (**(code **)(DAT_000020a0 + 0x50))(0x60000202,0x10,&LAB_00001460,0,&DAT_000020f8);
  (**(code **)(DAT_000020a0 + 0x50))(0x201,0x10,&DAT_0000145c,0,&DAT_00002108);
  FUN_00001474();
  (**(code **)(DAT_000020a0 + 0x170))(0x200,0x10,&LAB_000014d4,0,&DAT_00002040,&DAT_000020e8);
  (**(code **)(DAT_000020a0 + 0x170))(0x200,0x10,&LAB_000014fc,0,&DAT_00002030,&DAT_000020f0);
  return;
}

