/* iat_table.h - caller-owned import table (modules + funcs) (L1) */
#pragma once

#include "vmpx.h"

int      iat_table_init(iat_table_t* tab, uint32_t func_cap);
void     iat_table_reset(iat_table_t* tab);
void     iat_table_free(iat_table_t* tab);
int      iat_table_add_mod(iat_table_t* tab, const char* dll, uint32_t first_thunk);
int      iat_table_add_func(iat_table_t* tab);
uint32_t iat_table_unresolved(const iat_table_t* tab);
