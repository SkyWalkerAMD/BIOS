
void reset_flash(void)

{
  __gnu_mcount_nc();
  DataSynchronizationBarrier(0xf);
  DataSynchronizationBarrier(0xe);
  *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) =
       *(uint *)(_LANCHOR1 + ce_index * 4 + 0x10) & 0xf00ff3f | 0xb0041;
  return;
}

