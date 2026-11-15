
undefined4 maintenance_backup_configuration(void)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_000e1550;
  add_handler(*DAT_000e1550);
  add_handler(puVar1[1]);
  add_handler(puVar1[2]);
  return 0;
}

