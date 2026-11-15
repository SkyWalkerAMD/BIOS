
char * FUN_0000b4b4(longlong param_1,longlong param_2,longlong param_3,short *param_4,
                   longlong param_5,longlong param_6,longlong *param_7)

{
  longlong *plVar1;
  char *pcVar2;
  undefined1 *puVar3;
  longlong *plVar4;
  undefined1 *puVar5;
  
  if ((*(byte *)(param_2 + 0xe) & 2) == 0) {
    pcVar2 = (char *)0x8000000000000002;
  }
  else {
    puVar3 = FUN_00016b80();
    if (puVar3 == (undefined1 *)0x0) {
      pcVar2 = (char *)0x8000000000000009;
    }
    else {
      *(undefined4 *)(puVar3 + 0x18) = 6;
      plVar1 = *(longlong **)(param_3 + 0x10);
      if (*(longlong **)(param_3 + 0x10) == (longlong *)0x0) {
        *(undefined1 **)(param_3 + 0x10) = puVar3;
      }
      else {
        do {
          plVar4 = plVar1;
          plVar1 = (longlong *)*plVar4;
        } while ((longlong *)*plVar4 != (longlong *)0x0);
        *plVar4 = (longlong)puVar3;
        *(longlong **)(puVar3 + 8) = plVar4;
      }
      puVar5 = FUN_0001880c(*(char **)(param_2 + 0x88));
      FUN_00018744((longlong)puVar3,&DAT_0001a078,(longlong)puVar5);
      puVar5 = FUN_0001880c(*(char **)(param_2 + 0x90));
      FUN_00018744((longlong)puVar3,&DAT_00019eb4,(longlong)puVar5);
      if ((*(byte *)(param_2 + 0xe) & 4) != 0) {
        puVar5 = FUN_0001880c(*(char **)(param_2 + 0x98));
        FUN_00018744((longlong)puVar3,s_Description_00019f20,(longlong)puVar5);
      }
      FUN_0000b14c(param_1,(longlong)puVar3,param_2,param_4,param_5);
      pcVar2 = FUN_0000b428(param_2,(longlong)puVar3,param_6,param_7);
    }
  }
  return pcVar2;
}

