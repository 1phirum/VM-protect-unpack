/* vmtrans.h - VM entry/exit transition observer */
#pragma once

#include <stdint.h>

void vmtrans_track(uint32_t tid, uint32_t eip, uint32_t esp,
                   int private_exec, int in_image,
                   const uint8_t* data, uint32_t len);
