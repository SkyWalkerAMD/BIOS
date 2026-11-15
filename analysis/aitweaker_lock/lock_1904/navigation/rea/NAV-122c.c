
undefined8 Candidate_BrowserStatusExit(undefined8 param_1)

{
  undefined8 *puVar1;
  
  FUN_0000db6c();
  DAT_00082648 = 0;
  puVar1 = *(undefined8 **)(DAT_000824c0 + 0x40);
  if (puVar1 != (undefined8 *)0x0) {
    (*(code *)*puVar1)(puVar1,0);
    (**(code **)(*(longlong *)(DAT_000824c0 + 0x40) + 0x30))(*(longlong *)(DAT_000824c0 + 0x40));
    (**(code **)(*(longlong *)(DAT_000824c0 + 0x40) + 0x40))(*(longlong *)(DAT_000824c0 + 0x40),0);
  }
  return param_1;
}

