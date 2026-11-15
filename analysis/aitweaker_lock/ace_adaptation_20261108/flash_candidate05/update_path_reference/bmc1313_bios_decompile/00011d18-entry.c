
void processEntry entry(void)

{
  if (*(int *)(DAT_00011d34 + 73000 + DAT_00011d38) == 0) {
    return;
  }
  (*(code *)PTR___gmon_start___00026088)();
  return;
}

