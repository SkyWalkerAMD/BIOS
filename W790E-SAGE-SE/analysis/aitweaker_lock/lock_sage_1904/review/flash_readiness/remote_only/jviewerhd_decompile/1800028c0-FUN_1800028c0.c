
undefined8 FUN_1800028c0(longlong param_1)

{
  if (*(char *)(param_1 + 0x18) != '\0') {
    FUN_1800025c0(param_1);
    *(undefined1 *)(param_1 + 0x18) = 0;
    *(undefined1 *)(param_1 + 0x24) = 0;
  }
  return 0;
}

