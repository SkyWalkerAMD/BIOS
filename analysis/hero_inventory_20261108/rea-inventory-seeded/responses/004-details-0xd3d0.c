
undefined8 FUN_0000d3d0(longlong param_1,char *param_2,longlong param_3,byte param_4)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  longlong lVar4;
  char *pcVar5;
  undefined8 uVar6;
  
  if (param_1 == 0) {
    uVar6 = 0x8000000000000002;
  }
  else {
    puVar1 = FUN_00016b80();
    if (puVar1 != (undefined1 *)0x0) {
      *(undefined4 *)(puVar1 + 0x18) = 6;
      FUN_00018744(param_1,s_ProcessorSummary_0001c0d8,(longlong)puVar1);
      puVar2 = FUN_00016b80();
      if (puVar2 != (undefined1 *)0x0) {
        *(undefined4 *)(puVar2 + 0x18) = 6;
        FUN_00018744((longlong)puVar1,s_Status_00019fc8,(longlong)puVar2);
        puVar3 = FUN_0001880c(s_Enabled_00019ca8);
        FUN_00018744((longlong)puVar2,s_State_00019fa8,(longlong)puVar3);
        puVar3 = FUN_0001880c(&DAT_00019d2c);
        FUN_00018744((longlong)puVar2,s_Health_00019fb0,(longlong)puVar3);
        pcVar5 = s_Critical_00019d20;
        if ((param_4 & 1) == 0) {
          pcVar5 = &DAT_00019d2c;
        }
        puVar3 = FUN_0001880c(pcVar5);
        FUN_00018744((longlong)puVar2,s_HealthRollup_00019fb8,(longlong)puVar3);
        if (param_2 != (char *)0x0) {
          puVar2 = FUN_0001880c(param_2);
          FUN_00018744((longlong)puVar1,s_Model_00019f40,(longlong)puVar2);
        }
        if (param_3 == 0) {
          return 0;
        }
        lVar4 = FUN_000187d8(param_3);
        FUN_00018744((longlong)puVar1,s_Count_0001c0ec,lVar4);
        return 0;
      }
    }
    uVar6 = 0x8000000000000009;
  }
  return uVar6;
}

