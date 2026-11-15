
/* WARNING: Type propagation algorithm not settling */

void FUN_000164e0(longlong param_1)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  longlong local_res10 [2];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_res10[0] = 0;
  local_28 = 0xa3a3b874;
  local_res10[1] = 0x59ab;
  local_24 = 0x41827636;
  local_20 = 0x2cf51eba;
  local_1c = 0xe3944458;
  lVar1 = (**(code **)(DAT_00048460 + 0x40))(4,0x59ab,local_res10);
  if ((-1 < lVar1) &&
     (lVar1 = (**(code **)(DAT_00048468 + 0x48))
                        (u_VARSTORE_OCMR_SETTINGS_NAME_00041870,&local_28,0,local_res10 + 1,
                         local_res10[0]), -1 < lVar1)) {
    if ((param_1 + 0x486 == local_res10[0] + 0x486) ||
       (lVar1 = FUN_00001040(param_1 + 0x486,local_res10[0] + 0x486,0x2ca), lVar1 == 0)) {
      lVar1 = local_res10[0];
      uVar3 = 0;
      do {
        if (((*(longlong *)((longlong)&DAT_00030dc8 + uVar3) != 0) &&
            (*(longlong *)((longlong)&DAT_00030dc0 + uVar3) + param_1 !=
             *(longlong *)((longlong)&DAT_00030dc0 + uVar3) + lVar1)) &&
           (lVar2 = FUN_00001040(), lVar2 != 0)) goto code_r0x000165d5;
        uVar3 = uVar3 + 0x10;
      } while (uVar3 < 0x1b0);
    }
    else {
code_r0x000165d5:
      out(0x70,0x4b);
      out(0x71,1);
    }
    (**(code **)(DAT_00048460 + 0x48))(local_res10[0]);
  }
  return;
}

