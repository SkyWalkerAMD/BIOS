
void FUN_00000828(undefined8 param_1,longlong param_2)

{
  code *pcVar1;
  ushort uVar2;
  
  if ((param_2 != 0) && (*(longlong *)(param_2 + 0x18) != 0)) {
    uVar2 = 0;
    pcVar1 = FUN_00002a14;
    while (pcVar1 != (code *)0x0) {
      (*pcVar1)(param_1,*(undefined2 *)(param_2 + 0x10));
      uVar2 = uVar2 + 1;
      pcVar1 = (code *)(&PTR_FUN_0000d340)[uVar2];
    }
  }
  return;
}

