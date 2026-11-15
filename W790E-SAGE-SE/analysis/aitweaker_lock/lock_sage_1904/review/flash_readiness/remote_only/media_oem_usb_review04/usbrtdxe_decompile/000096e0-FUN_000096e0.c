
char * FUN_000096e0(byte *param_1)

{
  longlong lVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  undefined8 uVar4;
  char *pcVar5;
  byte bVar6;
  ulonglong uVar7;
  undefined8 *local_38;
  undefined1 local_30;
  undefined1 uStack_2f;
  undefined6 uStack_2e;
  undefined2 local_28;
  undefined4 uStack_26;
  undefined2 uStack_22;
  undefined4 local_20;
  
  bVar6 = 0;
  do {
    puVar2 = (undefined8 *)FUN_00002f1c(1);
    if (puVar2 != (undefined8 *)0x0) {
      uStack_22 = 0;
      lVar1 = *(longlong *)(DAT_0001ab98 + 0x62);
      *(undefined1 *)puVar2 = 0x12;
      uVar7 = lVar1 + 0x40;
      *(undefined1 *)((longlong)puVar2 + 4) = 0x24;
      DAT_0001ab88 = 0;
      local_30 = 0xc;
      if (param_1[0x58] == 6) {
        local_30 = 6;
      }
      local_20 = 0;
      uStack_2f = 0x80;
      uStack_2e = (undefined6)uVar7;
      local_28 = (undefined2)(uVar7 >> 0x30);
      uStack_26 = 0x24;
      local_38 = puVar2;
      uVar3 = FUN_00009640((longlong)param_1,&local_38);
      FUN_000030f0(puVar2,1);
      pcVar5 = (char *)(-(ulonglong)((int)uVar3 != 0) & uVar7);
      if (pcVar5 != (char *)0x0) {
        param_1[0x5e] = 0xff;
        param_1[0x5f] = 0xff;
        uVar4 = FUN_0000a4b8(param_1,pcVar5);
        if ((char)uVar4 != -1) {
          return pcVar5;
        }
        return (char *)0x0;
      }
    }
    if (((*(byte *)(DAT_0001b2c0 + 0x6c2) & 1) == 0) || (bVar6 = bVar6 + 1, 1 < bVar6)) {
      return (char *)0x0;
    }
  } while( true );
}

