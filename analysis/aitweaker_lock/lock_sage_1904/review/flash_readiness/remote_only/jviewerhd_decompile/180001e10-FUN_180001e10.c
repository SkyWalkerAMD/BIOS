
ulonglong * FUN_180001e10(ulonglong *param_1,void *param_2,ulonglong param_3)

{
  ulonglong uVar1;
  code *pcVar2;
  ulonglong *puVar3;
  
  if (param_2 != (void *)0x0) {
    uVar1 = param_1[3];
    puVar3 = param_1;
    if (0xf < uVar1) {
      puVar3 = (ulonglong *)*param_1;
    }
    if (puVar3 <= param_2) {
      puVar3 = param_1;
      if (0xf < uVar1) {
        puVar3 = (ulonglong *)*param_1;
      }
      if (param_2 < (void *)((longlong)puVar3 + param_1[2])) {
        puVar3 = param_1;
        if (0xf < uVar1) {
          puVar3 = (ulonglong *)*param_1;
        }
        puVar3 = (ulonglong *)
                 FUN_180001d00((longlong *)param_1,(longlong *)param_1,
                               (longlong)param_2 - (longlong)puVar3,param_3);
        return puVar3;
      }
    }
  }
  if (param_3 == 0xffffffffffffffff) {
    FUN_1800049bc("string too long");
    pcVar2 = (code *)swi(3);
    puVar3 = (ulonglong *)(*pcVar2)();
    return puVar3;
  }
  if (param_1[3] < param_3) {
    FUN_180001bc0(param_1,param_3,param_1[2]);
    if (param_3 == 0) {
      return param_1;
    }
  }
  else if (param_3 == 0) {
    param_1[2] = 0;
    if (0xf < param_1[3]) {
      *(undefined1 *)*param_1 = 0;
      return param_1;
    }
    *(undefined1 *)param_1 = 0;
    return param_1;
  }
  puVar3 = param_1;
  if (0xf < param_1[3]) {
    puVar3 = (ulonglong *)*param_1;
  }
  memcpy(puVar3,param_2,param_3);
  param_1[2] = param_3;
  puVar3 = param_1;
  if (0xf < param_1[3]) {
    puVar3 = (ulonglong *)*param_1;
  }
  *(undefined1 *)((longlong)puVar3 + param_3) = 0;
  return param_1;
}

