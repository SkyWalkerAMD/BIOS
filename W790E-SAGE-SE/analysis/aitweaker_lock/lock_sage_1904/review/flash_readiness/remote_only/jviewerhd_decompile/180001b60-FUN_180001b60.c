
longlong FUN_180001b60(undefined8 param_1,size_t param_2)

{
  longlong lVar1;
  char *local_res10 [3];
  undefined **local_28 [5];
  
  lVar1 = 0;
  if ((param_2 != 0) && (lVar1 = FUN_18000506c(param_2), lVar1 == 0)) {
    local_res10[0] = (char *)0x0;
    std::exception::exception((exception *)local_28,local_res10);
    local_28[0] = std::bad_alloc::vftable;
                    /* WARNING: Subroutine does not return */
    _CxxThrowException(local_28,(ThrowInfo *)&DAT_180016558);
  }
  return lVar1;
}

