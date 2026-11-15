
longlong FUN_00001564(longlong param_1,longlong param_2)

{
  longlong lVar1;
  ushort uVar2;
  undefined1 local_res10 [8];
  char local_res18;
  byte local_res19;
  undefined1 local_res20;
  undefined1 local_res21;
  undefined4 local_res22;
  
  uVar2 = 0;
  if (param_2 == 0) {
    lVar1 = -0x7ffffffffffffffe;
  }
  else {
    do {
      local_res20 = *(undefined1 *)(param_2 + 1);
      local_res21 = *(undefined1 *)(param_2 + 2);
      local_res22 = 0x524c43;
      local_res10[0] = 2;
      lVar1 = (**(code **)(param_1 + 8))(param_1,10,0,0x47,&local_res20,6,&local_res18,local_res10);
      if (lVar1 < 0) {
        if ((local_res18 == -0x3b) && (lVar1 = FUN_00001514(param_1,param_2), lVar1 < 0)) {
          return lVar1;
        }
      }
      else if ((local_res19 & 0xf) == 1) {
        return 0;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x200);
    lVar1 = -0x7ffffffffffffff0;
  }
  return lVar1;
}

