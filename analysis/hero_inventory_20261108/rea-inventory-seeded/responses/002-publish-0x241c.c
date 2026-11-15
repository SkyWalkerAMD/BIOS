
undefined8 SerializeGroupCRC_from_disassembly(uint *param_1,longlong param_2)

{
  uint uVar1;
  undefined1 *puVar2;
  longlong lVar3;
  undefined8 uVar4;
  
  puVar2 = FUN_00016b80();
  if (puVar2 == (undefined1 *)0x0) {
    uVar4 = 0x8000000000000009;
  }
  else {
    uVar1 = param_1[1];
    *(undefined4 *)(puVar2 + 0x18) = 6;
    if (uVar1 != 0) {
      lVar3 = FUN_000187d8((ulonglong)param_1[1]);
      FUN_00018744((longlong)puVar2,&DAT_0001a3ac,lVar3);
    }
    if (param_1[2] != 0) {
      lVar3 = FUN_000187d8((ulonglong)param_1[2]);
      FUN_00018744((longlong)puVar2,&DAT_0001a3b4,lVar3);
    }
    if (*param_1 != 0) {
      lVar3 = FUN_000187d8((ulonglong)*param_1);
      FUN_00018744((longlong)puVar2,&DAT_0001a3b8,lVar3);
    }
    FUN_00018744(param_2,s_GroupCrcList_0001a3c0,(longlong)puVar2);
    uVar4 = 0;
  }
  return uVar4;
}

