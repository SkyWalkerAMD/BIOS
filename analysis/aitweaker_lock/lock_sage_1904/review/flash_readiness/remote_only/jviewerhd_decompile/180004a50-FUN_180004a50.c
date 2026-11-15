
exception * FUN_180004a50(exception *param_1,exception *param_2)

{
  std::exception::exception(param_1,param_2);
  *(undefined ***)param_1 = std::out_of_range::vftable;
  return param_1;
}

