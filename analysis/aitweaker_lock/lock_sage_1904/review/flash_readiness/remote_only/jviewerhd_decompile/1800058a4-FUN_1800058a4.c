
type_info * FUN_1800058a4(type_info *param_1,uint param_2)

{
  *(undefined ***)param_1 = type_info::vftable;
  type_info::_Type_info_dtor(param_1);
  if ((param_2 & 1) != 0) {
    free(param_1);
  }
  return param_1;
}

