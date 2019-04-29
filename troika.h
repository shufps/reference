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
#define SIMD_SIZE 128

// simd-datetype for calculations
#if SIMD_SIZE == 128
#include <xmmintrin.h>
#define SIMD_T	__m128i
#elif SIMD_SIZE == 64
#define SIMD_T	uint64_t
#endif

typedef struct {
	SIMD_T hi;
	SIMD_T lo;
} Trit;

//typedef unsigned char Trit; /* Stores 0,1,2 in a byte. */
typedef unsigned char Tryte; /* Stores 0,...,26 in a byte. */

#define NUM_ROUNDS 24
#define TROIKA_RATE 243



/*
 * Evaluates the Troika hash function on the input.
 *
 * @param out    Pointer to the output buffer.
 * @param outlen Length of the output to be generated in trits.
 * @param input  Pointer to the input buffer.
 * @param inlen  Length of the input buffer in trits.
 *
 */
void Troika(Trit *out, unsigned long long outlen,
            const Trit *in, unsigned long long inlen);

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
void TroikaVarRounds(Trit *out, unsigned long long outlen,
                     const Trit *in, unsigned long long inlen,
                     unsigned long long num_rounds);
/*
 * Prints the state in a nice format.
 *
 * @param state Pointer to the state which is printed.
 */
void PrintTroikaSlice(uint8_t *state, int slice);
void PrintTroikaState(uint8_t *state);

void SubTrytes(Trit *state);
void ShiftRows(Trit *state);
void ShiftLanes(Trit *state);
void AddColumnParity(Trit *state);
void AddRoundConstant(Trit *state, int round);
void TroikaPermutation(Trit *state, unsigned long long num_rounds);


#endif
