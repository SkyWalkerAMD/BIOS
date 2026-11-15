
void Candidate_ACE_SaveStay(undefined8 param_1,undefined8 param_2,word *param_3)

{
  undefined8 uVar1;
  
  uVar1 = Candidate_ACE_SaveIterator(0x6b510,param_2,param_3);
  DAT_00082738 = 0;
  if ((char)uVar1 != '\0') {
    DAT_00082741 = 1;
  }
  return;
}

