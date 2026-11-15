
undefined8 FUN_00002d30(longlong param_1)

{
  if ((((*(short *)(param_1 + 0x26) == 0xef1) && (*(uint *)(param_1 + 0x18) < 0x2001001)) &&
      (*(uint *)(param_1 + 0x10) < 0x1001)) &&
     (((*(uint *)(param_1 + 0x10) <= *(uint *)(param_1 + 0x18) &&
       (*(uint *)(param_1 + 0x10) == (uint)*(ushort *)(param_1 + 0x1c))) &&
      (((ulonglong)*(ushort *)(param_1 + 0x1e) + 0x30 <= (ulonglong)*(ushort *)(param_1 + 0x1c) &&
       ((ulonglong)*(uint *)(param_1 + 0x20) + 0x20 <= (ulonglong)*(ushort *)(param_1 + 0x1e)))))))
  {
    return 1;
  }
  return 0;
}

