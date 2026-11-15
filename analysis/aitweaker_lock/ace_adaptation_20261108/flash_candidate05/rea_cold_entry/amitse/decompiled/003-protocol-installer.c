
void Candidate_ACE1904_protocol_installer(void)

{
  longlong lVar1;
  undefined8 local_res8;
  undefined8 local_res10 [3];
  
  lVar1 = (**(code **)(DAT_000824c8 + 0x148))
                    (&DAT_00082610,&DAT_0006a780,&PTR_Candidate_ACE1904_boot_manager_0006ab40,0);
  if (-1 < lVar1) {
    local_res8 = DAT_00082610;
    FUN_00020e20();
    FUN_00020ee4(local_res8);
    (**(code **)(DAT_000824c8 + 0x148))
              (&local_res8,&DAT_0006a8c0,&PTR_Candidate_ACE1904_external_send_form_0006b528,0);
    local_res10[0] = DAT_00082610;
    (**(code **)(DAT_000824c8 + 0x148))(local_res10,&DAT_0006a290,&PTR_LAB_0006ab38,0);
    local_res8 = DAT_00082610;
    (**(code **)(DAT_000824c8 + 0x148))(&local_res8,&DAT_0006a3d0,&PTR_DAT_0006ab20,0);
    local_res8 = DAT_00082610;
    FUN_0000447c(DAT_00082610);
    (**(code **)(DAT_000824c8 + 0x148))(&local_res8,&DAT_0006a620,&DAT_0006abd0,0);
  }
  return;
}

