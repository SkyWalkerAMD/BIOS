
longlong FUN_000b1684(longlong param_1,undefined2 param_2,char *param_3,undefined8 param_4,
                     undefined8 param_5)

{
  longlong lVar1;
  undefined1 *puVar2;
  char *pcVar3;
  undefined8 *puVar4;
  longlong lVar5;
  
  if ((DAT_00190c20 != 0) ||
     (lVar1 = (**(code **)(DAT_00190c28 + 0x140))(&DAT_0013bc18,0,&DAT_00190c20), -1 < lVar1)) {
    puVar2 = FUN_000b113c('\0');
    pcVar3 = (char *)FUN_000b13bc(param_1);
    if (pcVar3 != (char *)0x0) {
      puVar4 = FUN_000b129c(pcVar3,param_3,puVar2,&DAT_0016c1a4);
      if (puVar4 == (undefined8 *)0x0) {
        lVar5 = -0x7ffffffffffffff2;
      }
      else {
        lVar5 = (**(code **)(DAT_00190c20 + 8))
                          (DAT_00190c20,puVar4,param_1,param_2,param_5,param_4,0);
        lVar1 = DAT_00190c28;
        (**(code **)(DAT_00190c28 + 0x48))(puVar4);
        if (lVar5 == -0x7fffffffffffffe0) {
          lVar5 = FUN_000b147c(pcVar3,lVar1,param_1,param_2,param_4,param_5);
        }
      }
      (**(code **)(DAT_00190c28 + 0x48))(pcVar3);
      return lVar5;
    }
  }
  return -0x7ffffffffffffff2;
}

