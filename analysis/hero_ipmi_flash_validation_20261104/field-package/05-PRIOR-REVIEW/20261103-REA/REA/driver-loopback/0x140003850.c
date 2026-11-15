
bool FUN_140003850(byte param_1,byte param_2,char *param_3,longlong param_4)

{
  if (param_1 == 6) {
    if (param_2 < 0x25) {
      if ((param_2 != 1) && (param_2 != 4)) {
        return false;
      }
    }
    else if (param_2 != 0x25) {
      if (param_2 == 0x42) {
        if (param_3 == (char *)0x0 || param_4 != 1) {
          return false;
        }
        return (byte)(*param_3 - 1U) < 0xb;
      }
      if (param_2 != 0x2f) {
        return false;
      }
    }
  }
  else {
    if (param_2 == 2 && param_1 == 0xc) {
      if ((((param_3 != (char *)0x0 && param_4 == 4) && ((byte)(*param_3 - 1U) < 0xb)) &&
          (param_3[2] == '\0')) && (param_3[3] == '\0')) {
        return param_3[1] == '\f' || (byte)(param_3[1] - 3U) < 4;
      }
      return false;
    }
    if (param_2 != 0x40 || (param_1 ^ 10) != 0) {
      if (param_2 != 0x43 || (param_1 ^ 10) != 0) {
        return false;
      }
      if (param_3 == (char *)0x0 || param_4 != 6) {
        return false;
      }
      if (*param_3 != '\0') {
        return false;
      }
      if (param_3[1] == '\0') {
        if (param_3[4] == '\0') {
          return param_3[5] == -1;
        }
        return false;
      }
      return false;
    }
  }
  return param_4 == 0;
}

