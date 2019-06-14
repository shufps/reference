/*
 * MIT License

 * Copyright (c) 2019 Cybercrypt A/S

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef TROIKA_H
#define TROIKA_H

#include <stdint.h>

#define COLUMNS 9
#define ROWS 3
#define SLICES 27
#define SLICESIZE COLUMNS*ROWS
#define STATESIZE COLUMNS*ROWS*SLICES
#define NUM_SBOXES SLICES*ROWS*COLUMNS/3

//typedef unsigned char Trit; /* Stores 0,1,2 in a byte. */
//typedef unsigned char Tryte; /* Stores 0,...,26 in a byte. */

#define NUM_ROUNDS 24
#define TROIKA_RATE 243

#define SIMD_SIZE 256

// simd-datetype for calculations
#if SIMD_SIZE == 256
#include <immintrin.h>
#define SIMD_T __m256i
#elif SIMD_SIZE == 128
#include <xmmintrin.h>
#define SIMD_T	__m128i
#elif SIMD_SIZE == 64
#define SIMD_T	uint64_t
#elif SIMD_SIZE == 32
#define SIMD_T uint32_t
#endif

typedef struct {
	SIMD_T hi;
	SIMD_T lo;
} SIMD_Trit;

typedef struct
{
	// hashing state
	SIMD_Trit state[STATESIZE];
/*	// buffer for leftovers TODO not used yet
	uint8_t message[TROIKA_RATE];
	// count of bytes in the message[] buffer
	unsigned rest;
	// size of a message block processed at once
	unsigned block_size;*/
} TROIKA_CTX;

/*
 * Evaluates the Troika hash function on the input.
 *
 * @param out    Pointer to the output buffer.
 * @param outlen Length of the output to be generated in trits.
 * @param input  Pointer to the input buffer.
 * @param inlen  Length of the input buffer in trits.
 *
 */
void Troika(SIMD_Trit *out, unsigned long long outlen,
            const SIMD_Trit *in, unsigned long long inlen);

/*
 * Evaluates the Troika hash function on the input with a variable
 * number of rounds of the permutation.
 *
 * @param out    Pointer to the output buffer.
 * @param outlen Length of the output to be generated in trits.
 * @param input  Pointer to the input buffer.
 * @param inlen  Length of the input buffer in trits.
 * @param rounds Number of rounds used for the permutation.
 *
 */
void TroikaVarRounds(SIMD_Trit *out, unsigned long long outlen,
                     const SIMD_Trit *in, unsigned long long inlen,
                     unsigned long long num_rounds);


#endif
