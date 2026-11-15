
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong Candidate_PasswordInputDialog(longlong param_1,undefined2 param_2,longlong *param_3)

{
  char cVar1;
  longlong lVar2;
  short *psVar3;
  longlong *plVar4;
  longlong local_res20;
  undefined8 local_58 [3];
  uint local_3c;
  undefined1 *local_30;
  
  local_res20 = 0;
  lVar2 = (*(code *)PTR_FUN_00078500)(&local_res20);
  if (-1 < lVar2) {
    FUN_00000360(local_58,0x40,0);
    (**(code **)(DAT_000824c8 + 0x160))
              (&DAT_0008b718,*(longlong *)(param_1 + 0x48),
               *(byte *)(*(longlong *)(param_1 + 0x48) + 1) & 0x7f);
    local_58[0] = 0xffffffffffffffff;
    if ((4 < DAT_0008b718) &&
       ((((DAT_0008b718 < 9 || (DAT_0008b718 == 0xf)) || ((byte)(DAT_0008b718 - 0x1a) < 3)) ||
        (DAT_0008b718 == 0x23)))) {
      _DAT_0008b71a = param_2;
    }
    local_3c = (*(uint *)(param_1 + 0x3c) ^ local_3c) & 0x20 ^ local_3c | 1;
    local_30 = &DAT_0008b718;
    (*(code *)PTR_FUN_00078560)(local_res20,*param_3);
    (*(code *)PTR_FUN_00078558)(local_res20,1);
    lVar2 = (*(code *)PTR_FUN_00078510)(local_res20,local_58);
    if (-1 < lVar2) {
      cVar1 = FUN_00054980(local_res20);
      if (cVar1 == '\0') {
        plVar4 = param_3;
        FUN_00005958(param_3);
        psVar3 = (short *)FUN_0003eea8(plVar4,(ulonglong)(DAT_00078490 + 1) * 2);
        *param_3 = (longlong)psVar3;
        if (psVar3 == (short *)0x0) {
          return -0x7ffffffffffffff7;
        }
        FUN_0003e700(psVar3,(ulonglong)(DAT_00078490 + 1),DAT_00078498);
      }
      else {
        lVar2 = -0x7ffffffffffffffd;
      }
    }
    (*(code *)PTR_FUN_00078508)(local_res20,1);
  }
  return lVar2;
}

