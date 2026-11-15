
exception * FUN_18000583c(exception *param_1,uint param_2)

{
  *(undefined ***)param_1 = std::exception::vftable;
  std::exception::_Tidy(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}

