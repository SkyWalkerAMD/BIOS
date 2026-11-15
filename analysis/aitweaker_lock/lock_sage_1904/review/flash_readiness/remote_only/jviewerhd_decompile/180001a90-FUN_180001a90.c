
undefined8 * FUN_180001a90(undefined8 *param_1,byte param_2)

{
  undefined8 *_Memory;
  
  _Memory = param_1;
  FUN_1800017d0(param_1);
  if ((param_2 & 1) != 0) {
    free(_Memory);
  }
  return param_1;
}

