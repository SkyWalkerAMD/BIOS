
void WS05_fd6c(longlong param_1,undefined *param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong local_18;
  ulonglong local_10;
  
  local_10 = 0;
  local_18 = 0;
  lVar1 = WS05_fcb4(param_1,(longlong *)&local_10,(longlong *)&local_18);
  uVar2 = local_10;
  if (lVar1 == 0) {
    (*(code *)param_2)(param_3,param_4);
  }
  else {
    for (; uVar2 <= local_18; uVar2 = uVar2 + 1) {
      (**(code **)(&DAT_000a9760 + uVar2 * 8))(param_3,param_4);
    }
  }
  return;
}

