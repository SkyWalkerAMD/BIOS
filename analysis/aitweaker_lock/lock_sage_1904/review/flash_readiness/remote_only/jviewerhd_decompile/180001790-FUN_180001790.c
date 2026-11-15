
exception * FUN_180001790(exception *param_1,uint param_2)

{
  *(undefined ***)param_1 = std::bad_alloc::vftable;
  FUN_18000582c(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}

