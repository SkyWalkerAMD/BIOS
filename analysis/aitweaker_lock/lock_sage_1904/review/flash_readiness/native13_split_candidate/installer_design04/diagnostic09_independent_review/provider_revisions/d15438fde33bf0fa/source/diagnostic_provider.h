#ifndef SAGE_DIAGNOSTIC_PROVIDER_H
#define SAGE_DIAGNOSTIC_PROVIDER_H
#include "split_owner.h"
#include "diagnostic09.h"
DIAG09_REGION *split_diagnostic_region(void);
void diagnostic_unconfigured(void);
void diagnostic_acknowledged(void);
ES diagnostic_verify_request(void);
#endif
