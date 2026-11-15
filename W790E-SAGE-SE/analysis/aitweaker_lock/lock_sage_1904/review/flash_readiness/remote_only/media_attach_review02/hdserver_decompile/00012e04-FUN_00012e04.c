
void FUN_00012e04(void)

{
  if ((DAT_00012e34 - DAT_00012e30 >> 2) / 2 == 0) {
    return;
  }
  if (DAT_00012e38 == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00012e2c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00012e38)();
  return;
}

