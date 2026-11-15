
void FUN_000111b4(void)

{
  if (DAT_000111d8 == DAT_000111d4) {
    return;
  }
  if (DAT_000111dc == (code *)0x0) {
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x000111d0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*DAT_000111dc)();
  return;
}

