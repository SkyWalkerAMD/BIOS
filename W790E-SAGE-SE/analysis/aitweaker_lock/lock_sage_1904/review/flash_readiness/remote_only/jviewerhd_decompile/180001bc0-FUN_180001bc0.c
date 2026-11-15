
void FUN_180001bc0(undefined8 *param_1,ulonglong param_2,size_t param_3)

{
  ulonglong uVar1;
  undefined8 *_Dst;
  ulonglong uVar2;
  undefined8 *_Src;
  ulonglong uVar3;
  char *local_res20;
  undefined **local_40 [4];
  
  uVar3 = param_2 | 0xf;
  if (uVar3 != 0xffffffffffffffff) {
    uVar1 = param_1[3];
    uVar2 = uVar1 >> 1;
    param_2 = uVar3;
    if ((uVar3 / 3 < uVar2) && (param_2 = 0xfffffffffffffffe, uVar1 <= -uVar2 - 2)) {
      param_2 = uVar2 + uVar1;
    }
  }
  _Dst = (undefined8 *)0x0;
  if ((param_2 + 1 != 0) &&
     (_Dst = (undefined8 *)FUN_18000506c(param_2 + 1), _Dst == (undefined8 *)0x0)) {
    local_res20 = (char *)0x0;
    std::exception::exception((exception *)local_40,&local_res20);
    local_40[0] = std::bad_alloc::vftable;
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_40,(ThrowInfo *)&DAT_180016558);
  }
  if (param_3 != 0) {
    _Src = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      _Src = (undefined8 *)*param_1;
    }
    memcpy(_Dst,_Src,param_3);
  }
  if (0xf < (ulonglong)param_1[3]) {
    free((void *)*param_1);
  }
  *(undefined1 *)param_1 = 0;
  *param_1 = _Dst;
  param_1[3] = param_2;
  param_1[2] = param_3;
  if (0xf < param_2) {
    param_1 = _Dst;
  }
  *(undefined1 *)((longlong)param_1 + param_3) = 0;
  return;
}

