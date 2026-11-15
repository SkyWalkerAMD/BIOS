
longlong FUN_00003d30(byte *param_1,longlong param_2)

{
  undefined8 *puVar1;
  longlong lVar2;
  
  lVar2 = 0;
  if (((*param_1 != 0) && ((param_1[2] & 1) != 0)) && ((param_1[2] & 2) != 0)) {
    puVar1 = (undefined8 *)FUN_00016b80();
    if (puVar1 == (undefined8 *)0x0) {
      lVar2 = -0x7ffffffffffffff7;
    }
    else {
      *(undefined4 *)(puVar1 + 3) = 6;
      lVar2 = FUN_00003c08(param_1,(longlong)puVar1);
      if (lVar2 < 0) {
        FUN_00016bcc(puVar1);
      }
      else {
        FUN_00018744(param_2,s_Assembly_0001a110,(longlong)puVar1);
      }
    }
  }
  return lVar2;
}

