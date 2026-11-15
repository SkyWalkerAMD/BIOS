
void WS05_8eefc(longlong *param_1)

{
  longlong *plVar1;
  longlong *plVar2;
  
  plVar2 = DAT_000b8c28;
  if ((param_1 != (longlong *)0x0) &&
     (plVar1 = (longlong *)*param_1, (longlong *)*param_1 != (longlong *)0x0)) goto LAB_0008ef2c;
  DAT_000b8c28 = (longlong *)0x0;
  while (plVar1 = plVar2, plVar2 != (longlong *)0x0) {
LAB_0008ef2c:
    if (*plVar1 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
      *plVar1 = 0;
    }
    plVar2 = (longlong *)plVar1[2];
    (**(code **)(DAT_000afbc8 + 0x48))(plVar1);
  }
  if ((param_1 != (longlong *)0x0) && (*param_1 != 0)) {
    *param_1 = 0;
  }
  return;
}

