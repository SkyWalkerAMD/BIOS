
undefined4 settings_ntp_configuration(void)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_00089a2c;
  add_handler(*DAT_00089a2c);
  add_handler(puVar1[1]);
  add_handler(puVar1[2]);
  return 0;
}

