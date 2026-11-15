
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_18000506c(size_t param_1)

{
  int iVar1;
  void *pvVar2;
  char *local_res10 [3];
  undefined **local_28 [4];
  
  do {
    pvVar2 = malloc(param_1);
    if (pvVar2 != (void *)0x0) {
      return;
    }
    iVar1 = _callnewh(param_1);
  } while (iVar1 != 0);
  if ((DAT_180019638 & 1) == 0) {
    DAT_180019638 = DAT_180019638 | 1;
    local_res10[0] = "bad allocation";
    FUN_180005704((undefined8 *)&DAT_180019620,local_res10);
    _DAT_180019620 = std::bad_alloc::vftable;
    atexit((_func_5014 *)&LAB_180011ca0);
  }
  std::exception::exception((exception *)local_28,(exception *)&DAT_180019620);
  local_28[0] = std::bad_alloc::vftable;
                    /* WARNING: Subroutine does not return */
  _CxxThrowException(local_28,(ThrowInfo *)&DAT_180016558);
}

