/* Packaging relocation fixture only. No password, firmware service or driver. */
#include <stdint.h>
static volatile uint8_t zero_area[0x22003];
static volatile uint64_t value = UINT64_C(0x4c4b5041434b3035);
static volatile uint64_t *volatile pointer = &value;
__declspec(dllexport) volatile uint64_t *const fixture_readonly_pointer = &value;
static uint64_t adjust(uint64_t v) { return v ^ UINT64_C(0x1234567812345678); }
static uint64_t (*volatile action)(uint64_t) = adjust;
__declspec(dllexport) uint64_t i05_fixture_entry(void *image, void *table) {
  if (image != (void *)0x11223344 || table != (void *)0x55667788 || zero_area[0x22002]) return 0;
  zero_area[0x22002] = 0x5a;
  return action(*pointer);
}
__declspec(dllexport) uint64_t i05_fixture_hook(void) { return UINT64_C(0x5052455041525345); }
