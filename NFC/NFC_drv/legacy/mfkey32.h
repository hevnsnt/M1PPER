/* See COPYING.txt for license details. */

/*
 * mfkey32.h - On-device Crypto-1 key recovery (Mfkey32)
 *
 * Recovers a 6-byte MIFARE Classic key from two captured authentication
 * sessions for the same (uid, sector, keyType). Uses the Garcia/Verdult
 * state-space attack on the 48-bit Crypto-1 LFSR with a split-register
 * (odd/even) representation.
 *
 * Inputs are the values captured by the listener while emulating a card:
 *   - uid       : 4-byte UID seen during anticollision
 *   - nt0/nt1   : plaintext card nonces (sent to reader)
 *   - nr0_enc   : ciphertext reader nonce, first session
 *   - ar0_enc   : ciphertext reader answer, first session
 *   - nr1_enc   : ciphertext reader nonce, second session
 *   - ar1_enc   : ciphertext reader answer, second session
 *
 * On success the recovered 48-bit key is written MSB-first into key_out[6].
 */

#ifndef MFKEY32_H_
#define MFKEY32_H_

#include <stdint.h>
#include <stdbool.h>

bool mfkey32_solve(uint32_t uid,
                   uint32_t nt0,  uint32_t nr0_enc, uint32_t ar0_enc,
                   uint32_t nt1,  uint32_t nr1_enc, uint32_t ar1_enc,
                   uint8_t key_out[6]);

#endif /* MFKEY32_H_ */
