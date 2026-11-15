/* Link-only test fixture. Executes only in Unicorn; no physical entry point.
 * Browser ownership is an explicit service-layer dependency stub. */
#include "lock.h"
/* Save feedback is outside this isolated EBS fixture. The integrated mode
 * executes its real object and local retirement function. */
void save_feedback_note_denial(ES status) {(void)status;}
volatile int fixture_owner=1,fixture_can_enter=1;
volatile unsigned fixture_end_calls;
int platform_session_owned(void) {return fixture_owner;}
int platform_can_enter(void) {return fixture_can_enter;}
void end_platform(void) {fixture_end_calls++;fixture_owner=0;fixture_can_enter=0;}
ES EA test_entry(HANDLE image,ST *st) {
 (void)image;system_table=st;
 return initialize_services() && install_variable_guard()?0:ERR(7);
}
