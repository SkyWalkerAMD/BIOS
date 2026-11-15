/* 0x347b8 */

void FUN_000347b8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4,
                 undefined8 param_5)

{
  longlong lVar1;
  
  lVar1 = (**(code **)(DAT_00071fa8 + 0x50))(0x200,8,param_2,param_3,param_4);
  if (-1 < lVar1) {
    (**(code **)(DAT_00071fa8 + 0xa8))(param_1,*param_4,param_5);
  }
  return;
}

