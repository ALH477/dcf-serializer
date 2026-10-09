/* exsecutor: the C face of a library unit (exsc --emitte h). Generated,
 * never hand-edited: one prototype per `publica` function the unit defines,
 * spelled exactly as the unit's own prototype, then the one symbol the unit
 * imports. The host supplies exsrt_abortus; only a trap reaches it, and it
 * must not return. Above each prototype, its IR signature: a uint64_t carries
 * the named width in canonical form (a uN zero-extended, an iN sign-extended);
 * a value outside that width is outside the contract, and what the unit does
 * with one is unspecified. docs/design/c-backend.md D1, D5, D9. */
#ifndef EXSECUTOR_FACIES_A998B678DCBA2E98_H
#define EXSECUTOR_FACIES_A998B678DCBA2E98_H
#include <stdint.h>

/* (ptr, u64) -> u8 */
uint64_t exs_admitte_caput(unsigned char *p0, uint64_t p1);
/* (ptr, u64) -> u8 */
uint64_t exs_admitte_corpus(unsigned char *p0, uint64_t p1);

_Noreturn void exsrt_abortus(unsigned kind);
#endif
