
void FUN_0000197c(longlong param_1)

{
  char cVar1;
  longlong lVar2;
  longlong lVar3;
  ulonglong uVar4;
  
  FUN_0000e414(param_1);
  lVar2 = *(longlong *)(param_1 + 0x338);
  uVar4 = 0;
  if (*(longlong *)(param_1 + 0x330) != 0) {
    do {
      lVar3 = *(longlong *)(lVar2 + uVar4 * 8);
      cVar1 = *(char *)(lVar3 + 0x18);
      if (cVar1 == '\x01') {
        FUN_0000b808(param_1,lVar3);
      }
      else if (cVar1 == '\x02') {
LAB_00001a24:
        FUN_0000a634(param_1,lVar3);
      }
      else if (cVar1 == '\x03') {
        FUN_0000dc40(param_1,lVar3);
      }
      else if (cVar1 == '\x04') {
        FUN_0000880c(param_1,lVar3);
      }
      else if (cVar1 == '\x05') {
        FUN_00008a0c(param_1,lVar3);
      }
      else if (cVar1 == '\x06') {
        FUN_00008df0(param_1,lVar3);
      }
      else if (cVar1 == '\a') {
        FUN_000118c0(param_1,lVar3);
      }
      else {
        if (cVar1 == '\b') goto LAB_00001a24;
        if (cVar1 == '\t') {
          FUN_000091b0(param_1,lVar3);
        }
      }
      uVar4 = uVar4 + 1;
    } while (uVar4 < *(ulonglong *)(param_1 + 0x330));
  }
  return;
}

