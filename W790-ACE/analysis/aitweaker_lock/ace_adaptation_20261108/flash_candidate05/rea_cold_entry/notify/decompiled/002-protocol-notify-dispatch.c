
void Candidate_ACE1904_protocol_notify_dispatch(undefined8 param_1,undefined8 *param_2)

{
  longlong lVar1;
  undefined8 *local_res10;
  longlong local_res18 [2];
  undefined1 local_28 [16];
  
  if (param_2 != (undefined8 *)0x0) {
    local_res18[0] = 0;
    local_res10 = (undefined8 *)0x0;
    local_res18[1] = 0;
    if (DAT_00082628 < 4) {
      do {
        lVar1 = (**(code **)(DAT_000824c8 + 0x138))(1,0,param_2[5],local_res18,&local_res10);
        if (lVar1 < 0) {
          return;
        }
        if (local_res18[0] == 0) {
          return;
        }
        lVar1 = (**(code **)(DAT_000824c8 + 0x98))(*local_res10,&DAT_0006a520,local_28);
        if ((*(char *)(param_2 + 4) == '\0') || (-1 < lVar1)) {
          *param_2 = *local_res10;
          FUN_00005958((longlong *)&local_res10);
          (**(code **)(DAT_000824c8 + 0x98))(*param_2,param_2[3],param_2 + 6);
          if ((undefined8 *)param_2[7] != (undefined8 *)0x0) {
            *(undefined8 *)param_2[7] = param_2[6];
          }
          lVar1 = DAT_000824c0;
          if ((*(uint *)(param_2 + 2) & DAT_000826d4) != 0) {
            return;
          }
          if (*(int *)(param_2 + 2) == 4) {
            if (*(longlong *)(DAT_000824c0 + 0x30) != 0) {
              DAT_000826d4 = DAT_000826d4 | 4;
              *(undefined8 *)(DAT_000824c0 + 0x28) = *(undefined8 *)(DAT_000824c0 + 0x38);
            }
          }
          else {
            DAT_000826d4 = DAT_000826d4 | *(uint *)(param_2 + 2);
          }
          if (((byte)DAT_000826d4 & 0xb) != 0xb) {
            return;
          }
          if (DAT_00082638 == 0) {
            FUN_00007a78((ulonglong)DAT_000826d4,lVar1);
            lVar1 = DAT_000824c0;
          }
          if ((char)(DAT_000826d4 & 0xb) != '\v') {
            return;
          }
          if (*(longlong *)(lVar1 + 0x30) == 0) {
            return;
          }
          if (DAT_00082670 != '\0') {
            return;
          }
          DAT_00082670 = 1;
          FUN_00007dd4((ulonglong)(DAT_000826d4 & 0xb));
          return;
        }
        FUN_00005958((longlong *)&local_res10);
      } while (local_res18[0] != 0);
    }
  }
  return;
}

