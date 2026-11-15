
void FUN_00012dd8(void)

{
  if (DAT_00012dfc == DAT_00012df8) {
    return;
  }
  if (DAT_00012e00 == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00012df4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00012e00)();
  return;
}

