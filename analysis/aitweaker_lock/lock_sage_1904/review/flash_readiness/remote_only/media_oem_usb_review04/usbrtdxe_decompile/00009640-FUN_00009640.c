
ulonglong FUN_00009640(longlong param_1,undefined8 *param_2)

{
  longlong lVar1;
  code *pcVar2;
  uint uVar3;
  ulonglong uVar4;
  longlong lVar5;
  undefined4 extraout_var;
  
  if (*(byte *)(param_1 + 0x59) < 2) {
    uVar3 = FUN_0000b768(param_1,param_2);
    uVar4 = CONCAT44(extraout_var,uVar3);
  }
  else if (*(byte *)(param_1 + 0x59) == 0x50) {
    *(undefined1 *)(DAT_0001b2c0 + 0x6c4) = 0;
    uVar4 = FUN_0000b4f4(param_1,param_2);
    uVar4 = uVar4 & 0xffffffff;
    *(undefined1 *)(DAT_0001b2c0 + 0x6c4) = 1;
    lVar1 = *(longlong *)(DAT_0001aba8 + (longlong)(int)(*(byte *)(param_1 + 0xb) - 1) * 8);
    lVar5 = FUN_00019d08();
    if ((-1 < lVar5) &&
       (pcVar2 = *(code **)((ulonglong)
                            ((uint)((longlong)(ulonglong)(*(byte *)(lVar1 + 1) - 0x10) >> 4) & 3) *
                            200 + 0x30 + DAT_0001ac08), pcVar2 != (code *)0x0)) {
      (*pcVar2)(lVar1);
    }
  }
  else {
    uVar4 = 0;
  }
  return uVar4;
}

