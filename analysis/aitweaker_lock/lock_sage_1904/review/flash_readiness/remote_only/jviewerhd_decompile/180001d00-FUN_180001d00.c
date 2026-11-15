
longlong * FUN_180001d00(longlong *param_1,longlong *param_2,ulonglong param_3,ulonglong param_4)

{
  code *pcVar1;
  longlong *plVar2;
  ulonglong _Size;
  
  if ((ulonglong)param_2[2] < param_3) {
    FUN_180004a18("invalid string position");
    pcVar1 = (code *)swi(3);
    plVar2 = (longlong *)(*pcVar1)();
    return plVar2;
  }
  _Size = param_2[2] - param_3;
  if (param_4 < _Size) {
    _Size = param_4;
  }
  if (param_1 == param_2) {
    FUN_180001ac0(param_1,_Size + param_3,0xffffffffffffffff);
    FUN_180001ac0(param_1,0,param_3);
  }
  else {
    if (_Size == 0xffffffffffffffff) {
      FUN_1800049bc("string too long");
      pcVar1 = (code *)swi(3);
      plVar2 = (longlong *)(*pcVar1)();
      return plVar2;
    }
    if ((ulonglong)param_1[3] < _Size) {
      FUN_180001bc0(param_1,_Size,param_1[2]);
      if (_Size == 0) {
        return param_1;
      }
    }
    else if (_Size == 0) {
      param_1[2] = 0;
      if (0xf < (ulonglong)param_1[3]) {
        *(undefined1 *)*param_1 = 0;
        return param_1;
      }
      *(undefined1 *)param_1 = 0;
      return param_1;
    }
    if (0xf < (ulonglong)param_2[3]) {
      param_2 = (longlong *)*param_2;
    }
    plVar2 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      plVar2 = (longlong *)*param_1;
    }
    memcpy(plVar2,(void *)((longlong)param_2 + param_3),_Size);
    param_1[2] = _Size;
    plVar2 = param_1;
    if (0xf < (ulonglong)param_1[3]) {
      plVar2 = (longlong *)*param_1;
    }
    *(undefined1 *)((longlong)plVar2 + _Size) = 0;
  }
  return param_1;
}

