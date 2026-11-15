
undefined8 FUN_180003470(longlong param_1)

{
  BOOL BVar1;
  int iVar2;
  LARGE_INTEGER local_res8 [4];
  
  local_res8[0].QuadPart = 0;
  BVar1 = GetFileSizeEx(*(HANDLE *)(param_1 + 0x108),local_res8);
  if (BVar1 == 0) {
    return 0xfffffff9;
  }
  iVar2 = (int)((ulonglong)local_res8[0].QuadPart >> 9);
  if ((local_res8[0].QuadPart & 0x1ffU) != 0) {
    iVar2 = iVar2 + 1;
  }
  *(undefined4 *)(param_1 + 0x118) = 0x200;
  *(int *)(param_1 + 0x11c) = iVar2;
  return 0;
}

