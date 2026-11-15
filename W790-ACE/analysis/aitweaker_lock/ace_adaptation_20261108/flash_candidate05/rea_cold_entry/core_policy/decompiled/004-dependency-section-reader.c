
longlong Candidate_ACE1904_dependency_section_reader(longlong param_1)

{
  undefined8 *puVar1;
  char *pcVar2;
  longlong lVar3;
  undefined1 local_res8 [8];
  
  puVar1 = (undefined8 *)(param_1 + 0x50);
  lVar3 = (**(code **)(*(longlong *)(param_1 + 0x48) + 0x18))
                    (*(longlong *)(param_1 + 0x48),param_1 + 0x30,0x13,0,puVar1,param_1 + 0x58,
                     local_res8);
  if (lVar3 < 0) {
    if (lVar3 == -0x7fffffffffffffe8) {
      *(undefined1 *)(param_1 + 0x79) = 1;
      return -0x7fffffffffffffe8;
    }
    *puVar1 = 0;
    *(undefined1 *)(param_1 + 0x74) = 1;
  }
  else {
    pcVar2 = (char *)*puVar1;
    if (*pcVar2 == '\t') {
      *(undefined1 *)(param_1 + 0x75) = 1;
    }
    else {
      *(undefined1 *)(param_1 + 0x74) = 1;
    }
    if (*pcVar2 == '\0') {
      *(undefined1 *)(param_1 + 0x60) = 1;
    }
    else if (*pcVar2 == '\x01') {
      *(undefined1 *)(param_1 + 0x61) = 1;
    }
    if ((*(char *)(param_1 + 0x60) != '\0') || (*(char *)(param_1 + 0x61) != '\0')) {
      if ((char *)(param_1 + 100) != pcVar2 + 1) {
        FUN_00000410((undefined8 *)(param_1 + 100),(undefined8 *)(pcVar2 + 1),0x10);
      }
    }
  }
  *(undefined1 *)(param_1 + 0x79) = 0;
  return lVar3;
}

