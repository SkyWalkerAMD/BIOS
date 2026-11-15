
void processEntry entry(void)

{
  if (*(int *)(DAT_00010e68 + 0x10e5c + DAT_00010e6c) == 0) {
    return;
  }
  (*(code *)PTR___gmon_start___0002305c)();
  return;
}

