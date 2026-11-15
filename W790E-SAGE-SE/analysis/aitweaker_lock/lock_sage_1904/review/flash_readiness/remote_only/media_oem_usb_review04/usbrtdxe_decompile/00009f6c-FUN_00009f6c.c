
undefined1 FUN_00009f6c(byte *param_1,uint param_2,undefined8 param_3)

{
  undefined8 *puVar1;
  ulonglong uVar2;
  undefined1 uVar3;
  char cVar4;
  bool bVar5;
  undefined8 *local_48;
  undefined1 local_40;
  undefined1 uStack_3f;
  undefined6 uStack_3e;
  undefined2 local_38;
  uint uStack_36;
  undefined2 uStack_32;
  undefined2 uStack_30;
  undefined2 uStack_2e;
  
  uVar3 = 0xff;
  puVar1 = (undefined8 *)FUN_00002f1c(1);
  if (puVar1 != (undefined8 *)0x0) {
    uStack_2e = 0;
    cVar4 = '\n';
    do {
      *(undefined1 *)puVar1 = 0x28;
      *(undefined2 *)((longlong)puVar1 + 7) = 0x100;
      *(uint *)((longlong)puVar1 + 2) =
           param_2 >> 0x18 | (param_2 & 0xff0000) >> 8 | (param_2 & 0xff00) << 8 | param_2 << 0x18;
      local_40 = 0xc;
      if (param_1[0x58] == 6) {
        local_40 = 10;
      }
      uStack_3f = 0x80;
      uStack_36 = (uint)*(ushort *)(param_1 + 0x5e);
      uStack_3e = (undefined6)param_3;
      local_38 = (undefined2)((ulonglong)param_3 >> 0x30);
      uStack_32 = 0;
      uStack_30 = 0;
      local_48 = puVar1;
      uVar2 = FUN_00009640((longlong)param_1,&local_48);
      if ((int)uVar2 != 0) {
        uVar3 = 0;
        break;
      }
      uVar2 = FUN_0000af54(param_1);
      uVar3 = 0xff;
      if ((int)uVar2 != 0) break;
      FUN_00000300(puVar1,0xc);
      bVar5 = cVar4 != '\0';
      cVar4 = cVar4 + -1;
    } while (bVar5);
    FUN_000030f0(puVar1,1);
  }
  return uVar3;
}

