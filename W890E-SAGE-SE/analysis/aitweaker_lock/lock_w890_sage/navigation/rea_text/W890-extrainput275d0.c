
undefined8 Observed_ExtraControlInput(longlong param_1,longlong param_2)

{
  char *pcVar1;
  longlong lVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  
  uVar4 = 0x8000000000000003;
  if (*(short *)(param_2 + 8) == 1) {
    pcVar1 = (char *)(param_2 + 0xc);
    if ((pcVar1 != (char *)(param_1 + 0x20)) &&
       (lVar2 = FUN_000015e0(pcVar1,(char *)(param_1 + 0x20),4), lVar2 != 0)) {
      return 0x8000000000000003;
    }
    uVar3 = FUN_0004de84((uint)((ulonglong)*(undefined8 *)pcVar1 >> 0x20),*(uint *)(param_1 + 0x24))
    ;
    if ((char)uVar3 != '\0') {
      if (*(code **)(param_1 + 8) != (code *)0x0) {
        (**(code **)(param_1 + 8))
                  (*(undefined8 *)(param_1 + 0x10),param_1,*(undefined8 *)(param_1 + 0x18));
      }
      (*(code *)PTR_FUN_00093dd8)(param_2);
      uVar4 = 0;
    }
  }
  return uVar4;
}

