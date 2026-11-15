
void Candidate_ACE1904_boot_manager_bridge(void)

{
  longlong *plVar1;
  longlong lVar2;
  longlong *plVar3;
  undefined8 *local_res8;
  undefined8 local_res10 [3];
  
  local_res8 = (undefined8 *)0x0;
  local_res10[0] = 0;
  (**(code **)(DAT_0001ff40 + 0x58))(u_BootOptionSupport_0001b7e8,&DAT_0001a310,6,4,&DAT_0001aa08);
  (**(code **)(DAT_0001ff40 + 0x58))
            (u_OsIndicationsSupported_0001b810,&DAT_0001a310,6,8,&DAT_0001aa10);
  (**(code **)(DAT_0001ff30 + 0x80))(local_res10,&DAT_0001a5f0,0,&DAT_0001a990);
  plVar3 = DAT_00020788;
  while (plVar3 != (longlong *)0x0) {
    plVar1 = (longlong *)*plVar3;
    FUN_00003d74(&DAT_00020780,plVar3);
    plVar3 = plVar1;
  }
  lVar2 = (**(code **)(DAT_0001ff30 + 0x140))(&DAT_0001a9f8,0,&local_res8);
  if (-1 < lVar2) {
    (*(code *)*local_res8)();
  }
  return;
}

