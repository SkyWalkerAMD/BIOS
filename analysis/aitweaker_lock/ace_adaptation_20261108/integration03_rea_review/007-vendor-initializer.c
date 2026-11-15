
ulonglong Candidate_ACE_VendorInitializer(undefined8 **param_1,ulonglong param_2)

{
  undefined8 uVar1;
  undefined1 *puVar2;
  word *pwVar3;
  
  DAT_0008b510 = 0;
  DAT_00082700 = 1;
  FUN_0005cc40(param_1,param_2);
  puVar2 = &LAB_00036c84;
  DAT_00082700 = 0;
  pwVar3 = DAT_00082660;
  FUN_00005b0c(0xffff001d,&LAB_00036c84,DAT_00082660,0);
  uVar1 = Candidate_ACE_SaveIterator(0,puVar2,pwVar3);
  return -(ulonglong)((char)uVar1 != '\x01') & 0x8000000000000015;
}

