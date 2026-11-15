
void processEntry entry(void)

{
  if (*(int *)(DAT_00010d88 + 0x10d7c + DAT_00010d8c) == 0) {
    return;
  }
  (*(code *)PTR___gmon_start___00023058)();
  return;
}

