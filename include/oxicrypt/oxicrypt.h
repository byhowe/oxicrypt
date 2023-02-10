#ifndef OXICRYPT_H_
#define OXICRYPT_H_

#if defined(__x86_64__) || defined(__i386__)
#define OXI_HAVE_X86
#endif

#if defined(__arm__) || defined(__aarch64__)
#define OXI_HAVE_ARM
#endif

#endif // OXICRYPT_H_
