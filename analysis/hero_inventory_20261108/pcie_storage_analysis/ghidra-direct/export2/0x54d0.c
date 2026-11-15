
ulonglong FUN_000054d0(undefined8 *param_1,longlong param_2,longlong param_3)

{
  longlong lVar1;
  short *psVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  ulonglong uVar5;
  short *local_res10;
  
  local_res10 = (short *)0x0;
  uVar5 = 0;
  uVar3 = (**(code **)(param_2 + 8))(param_2,s_SimpleStorage_0001ac70,&local_res10);
  if ((-1 < (longlong)uVar3) &&
     (((uVar3 = FUN_00019114(param_1,local_res10), -1 < (longlong)uVar3 ||
       (uVar3 = FUN_0001922c(param_1,local_res10), -1 < (longlong)uVar3)) &&
      (*(longlong *)(param_3 + 0x330) != 0)))) {
    do {
      lVar1 = *(longlong *)(*(longlong *)(param_3 + 0x338) + uVar5 * 8);
      if (*(char *)(lVar1 + 0x18) == '\x04') {
        psVar2 = *(short **)(lVar1 + 0x20);
        puVar4 = (undefined8 *)FUN_00016b80();
        if (puVar4 == (undefined8 *)0x0) {
          uVar3 = 0x8000000000000009;
        }
        else {
          *(undefined4 *)(puVar4 + 3) = 6;
          uVar3 = FUN_000096a8(lVar1 + 0x28,(longlong)puVar4,psVar2);
          if ((-1 < (longlong)uVar3) &&
             (uVar3 = FUN_000095ac(lVar1 + 0x28,(longlong)puVar4,param_3), -1 < (longlong)uVar3)) {
            uVar3 = FUN_00003eb4(param_1,(longlong)puVar4,local_res10);
            FUN_00016bcc(puVar4);
            if (-1 < (longlong)uVar3) goto LAB_000055c9;
            break;
          }
        }
        if (puVar4 != (undefined8 *)0x0) {
          FUN_00016bcc(puVar4);
        }
        break;
      }
LAB_000055c9:
      uVar5 = uVar5 + 1;
    } while (uVar5 < *(ulonglong *)(param_3 + 0x330));
  }
  if (local_res10 != (short *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))();
  }
  return uVar3;
}

