
void FUN_000111e0(void)

{
  if ((DAT_00011210 - DAT_0001120c >> 2) / 2 == 0) {
    return;
  }
  if (DAT_00011214 == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x00011208. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_00011214)();
  return;
}

