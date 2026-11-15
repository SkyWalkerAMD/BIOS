
void processEntry entry(void)

{
  if (*(int *)(DAT_00010e9c + 0x10e90 + DAT_00010ea0) == 0) {
    return;
  }
  (*(code *)PTR___gmon_start___0002403c)();
  return;
}

