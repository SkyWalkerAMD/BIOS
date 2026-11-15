
byte FUN_00009ebc(longlong param_1)

{
  undefined8 *puVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  undefined8 *local_28;
  undefined2 local_20;
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
    *(undefined2 *)((longlong)puVar1 + 7) = 0x800;
    *(undefined1 *)puVar1 = 0x46;
    local_20 = 0x800a;
    uStack_1e = SUB86(puVar2,0);
    local_18 = (undefined2)((ulonglong)puVar2 >> 0x30);
    uStack_16 = 8;
    local_28 = puVar1;
    uVar3 = FUN_00009640(param_1,&local_28);
    FUN_000030f0(puVar2,1);
    FUN_000030f0(puVar1,1);
    return ~-((int)uVar3 != 0);
  }
  return 0xff;
}

