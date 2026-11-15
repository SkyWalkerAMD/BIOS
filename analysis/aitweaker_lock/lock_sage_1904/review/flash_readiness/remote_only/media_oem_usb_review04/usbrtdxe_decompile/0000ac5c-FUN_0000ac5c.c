
int FUN_0000ac5c(longlong param_1)

{
  byte bVar1;
  int iVar2;
  undefined8 *puVar3;
  undefined8 *local_28;
  ulonglong local_20;
  undefined8 local_18;
  undefined4 local_10;
  
  if ((*(byte *)(param_1 + 0x7c) & 0x20) == 0) {
    puVar3 = (undefined8 *)FUN_00002f1c(1);
    if (puVar3 == (undefined8 *)0x0) {
      iVar2 = 0xff;
    }
    else {
      *(undefined1 *)puVar3 = 0x1b;
      *(undefined1 *)((longlong)puVar3 + 4) = 1;
      local_18 = 0;
      local_10 = 0;
      *(undefined2 *)(DAT_0001b2c0 + 0x6ae) = 10000;
      bVar1 = 0xc;
      if (*(char *)(param_1 + 0x58) == '\x06') {
        bVar1 = 6;
      }
      local_20 = (ulonglong)bVar1;
      local_28 = puVar3;
      FUN_00009640(param_1,&local_28);
      FUN_000030f0(puVar3,1);
      iVar2 = FUN_0000ae3c(param_1);
    }
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}

