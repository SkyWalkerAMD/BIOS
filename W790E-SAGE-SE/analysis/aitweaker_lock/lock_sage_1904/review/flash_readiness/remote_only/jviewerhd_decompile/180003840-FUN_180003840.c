
undefined8 FUN_180003840(longlong param_1)

{
  *(undefined1 *)(param_1 + 0x121) = 0;
  if (*(char *)(param_1 + 0x123) == '\x01') {
    if (*(int *)(param_1 + 0x110) < 1) {
      return 0;
    }
  }
  else if (*(longlong *)(param_1 + 0x108) == 0) {
    return 0;
  }
  CloseHandle(*(HANDLE *)(param_1 + 0x108));
  return 0;
}

