
char * FUN_0000b428(longlong param_1,longlong param_2,longlong param_3,longlong *param_4)

{
  undefined1 *puVar1;
  char *pcVar2;
  
  puVar1 = FUN_00016b80();
  if (puVar1 == (undefined1 *)0x0) {
    pcVar2 = (char *)0x8000000000000009;
  }
  else {
    *(undefined4 *)(puVar1 + 0x18) = 5;
    FUN_00018744(param_2,s_Redundancy_0001ac80,(longlong)puVar1);
    pcVar2 = FUN_00000f7c(*(longlong *)(param_1 + 0x18),(ulonglong)*(byte *)(param_1 + 0xc),
                          (longlong)puVar1,param_3,param_4);
  }
  return pcVar2;
}

