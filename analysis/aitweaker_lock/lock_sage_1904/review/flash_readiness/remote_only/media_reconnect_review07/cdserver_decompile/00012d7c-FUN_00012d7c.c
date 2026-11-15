
void FUN_00012d7c(void)

{
  if (DAT_00012da0 == DAT_00012d9c) {
    return;
  }
  if (DAT_00012da4 == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00012d98. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00012da4)();
  return;
}

