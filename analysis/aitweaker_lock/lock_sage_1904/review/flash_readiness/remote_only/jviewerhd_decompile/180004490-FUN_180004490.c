
void FUN_180004490(undefined8 param_1,undefined4 param_2,longlong param_3)

{
  switch(param_2) {
  case 0:
    *(undefined4 *)(param_3 + 0x35) = 0;
    return;
  case 0xfffffff1:
  case 0xfffffffb:
    *(undefined4 *)(param_3 + 0x35) = 0x3a0201;
    return;
  default:
    *(undefined4 *)(param_3 + 0x35) = 0x200501;
    return;
  case 0xfffffff3:
    *(undefined4 *)(param_3 + 0x35) = 0x270701;
    return;
  case 0xfffffff8:
    *(undefined4 *)(param_3 + 0x35) = 0x2530501;
    return;
  case 0xfffffff9:
    *(undefined4 *)(param_3 + 0x35) = 0x2300301;
    return;
  case 0xfffffffa:
    *(undefined4 *)(param_3 + 0x35) = 0x260501;
    return;
  case 0xfffffffc:
    *(undefined4 *)(param_3 + 0x35) = 0x110301;
    return;
  case 0xfffffffd:
    *(undefined4 *)(param_3 + 0x35) = 0x280601;
    return;
  case 0xfffffffe:
    *(undefined4 *)(param_3 + 0x35) = 0x1300300;
    return;
  case 0xffffffff:
    *(undefined4 *)(param_3 + 0x35) = 0x210501;
    return;
  }
}

