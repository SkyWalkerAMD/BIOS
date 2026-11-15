
undefined8 Candidate_ControlInitialize(longlong param_1,longlong param_2)

{
  (**(code **)(DAT_000afbc8 + 0x160))(param_1 + 0x20,param_2,4);
  *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_2 + 4);
  *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_2 + 0x10);
  return 0;
}

