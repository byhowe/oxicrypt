#ifndef OXICRYPT_OXICRYPT_H_
#define OXICRYPT_OXICRYPT_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t oxi_implementation_t;

void oxi_ctl_set_global_implementation(oxi_implementation_t implementation);
oxi_implementation_t oxi_ctl_get_global_implementation();

const oxi_implementation_t OXI_IMPL_GENERIC = 0;
const oxi_implementation_t OXI_IMPL_AES = 1 << 0;

oxi_implementation_t oxi_impl_fastest();
oxi_implementation_t oxi_impl_fastest_rt();
bool oxi_impl_is_available(oxi_implementation_t bits);

#ifdef __cplusplus
}
#endif

#endif // OXICRYPT_OXICRYPT_H_
