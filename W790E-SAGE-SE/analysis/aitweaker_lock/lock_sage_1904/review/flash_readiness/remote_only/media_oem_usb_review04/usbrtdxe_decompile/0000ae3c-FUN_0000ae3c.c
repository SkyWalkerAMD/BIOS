
int FUN_0000ae3c(longlong param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  int iVar4;
  undefined8 *local_28;
  undefined1 local_20;
  undefined1 uStack_1f;
  undefined6 uStack_1e;
  undefined2 local_18;
  undefined4 uStack_16;
  undefined2 uStack_12;
  undefined4 local_10;
  
  puVar1 = (undefined8 *)FUN_00002f1c(1);
  if ((puVar1 != (undefined8 *)0x0) &&
     (puVar2 = (undefined8 *)FUN_00002f1c(1), puVar2 != (undefined8 *)0x0)) {
    uStack_12 = 0;
    local_10 = 0;
    *(undefined1 *)puVar1 = 3;
    *(undefined1 *)((longlong)puVar1 + 4) = 0x12;
    uStack_1f = 0x80;
    local_20 = 0xc;
    if (*(char *)(param_1 + 0x58) == '\x06') {
      local_20 = 6;
    }
    uStack_1e = SUB86(puVar2,0);
    local_18 = (undefined2)((ulonglong)puVar2 >> 0x30);
    uStack_16 = 0x12;
    local_28 = puVar1;
    uVar3 = FUN_00009640(param_1,&local_28);
    if ((int)uVar3 == 0) {
      iVar4 = 0xff;
    }
    else {
      iVar4 = (uint)*(byte *)((longlong)puVar2 + 0xd) * 0x10000 +
              (uint)*(byte *)((longlong)puVar2 + 0xc) * 0x100 +
              (uint)*(byte *)((longlong)puVar2 + 2);
      if ((short)iVar4 == 0x3a02) {
        *(byte *)(param_1 + 0xa0) = *(byte *)(param_1 + 0xa0) & 0xfe;
      }
      if ((short)iVar4 == 0x2806) {
        *(byte *)(param_1 + 0xa0) = *(byte *)(param_1 + 0xa0) | 3;
      }
      if (iVar4 == 0) {
        *(byte *)(param_1 + 0xa0) = *(byte *)(param_1 + 0xa0) | 1;
      }
    }
    FUN_000030f0(puVar1,1);
    FUN_000030f0(puVar2,1);
    return iVar4;
  }
  return 0xff;
}

