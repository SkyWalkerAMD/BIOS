
void FUN_00012da8(void)

{
  if ((DAT_00012dd8 - DAT_00012dd4 >> 2) / 2 == 0) {
    return;
  }
  if (DAT_00012ddc == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00012dd0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00012ddc)();
  return;
}

