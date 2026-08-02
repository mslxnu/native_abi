#ifndef LINUX_RANDOM_H
#define LINUX_RANDOM_H

#define GRND_NONBLOCK 0x0001
#define GRND_RANDOM   0x0002
/*
 * "I do not need cryptographic quality, do not block for the entropy pool."
 * Added in Linux 5.6, and Rust's standard library asks for it first - so
 * rejecting it is not an obscure gap: it is every Rust program that wants a
 * random number. sqv, the OpenPGP verifier apt shells out to, got EINVAL here
 * and aborted, which is how apt came to report every Debian repository as
 * unsigned.
 */
#define GRND_INSECURE 0x0004

#endif
