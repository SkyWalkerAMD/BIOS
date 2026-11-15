
void Observed_MenuSelection(longlong param_1,ushort param_2)

{
  if ((*(longlong *)(param_1 + 8) != 0) && (*(longlong *)(param_1 + 0x18) != 0)) {
    *(undefined2 *)(*(longlong *)(param_1 + 0x18) + 8) =
         *(undefined2 *)(*(longlong *)(param_1 + 0x80) + 8 + (ulonglong)param_2 * 0x10);
    (**(code **)(param_1 + 8))
              (*(undefined8 *)(param_1 + 0x10),param_1,*(undefined8 *)(param_1 + 0x18));
  }
  return;
}

