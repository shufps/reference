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

#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "troika.h"

#include <sys/time.h>

#define COLUMNS 9
#define ROWS 3
#define SLICES 27
#define SLICESIZE COLUMNS*ROWS
#define STATESIZE COLUMNS*ROWS*SLICES
#define NUM_SBOXES SLICES*ROWS*COLUMNS/3

//#define PADDING 0x1
#if SIMD_SIZE==256
const Trit PADDING={~0, ~0, ~0, ~0};
#elif SIMD_SIZE==128
const Trit PADDING={~0, ~0, ~0, ~0};
#elif SIMD_SIZE==64
const Trit PADDING={~0ul, ~0ul};
#elif SIMD_SIZE==32
const Trit PADDING={~0, ~0};
#endif

static Trit simd_round_constants[NUM_ROUNDS][COLUMNS*SLICES];

uint16_t perm[729];
uint16_t plutLeft[243];
uint16_t plutRight[243];

static const uint8_t round_constants[NUM_ROUNDS][COLUMNS*SLICES] = {
 {2, 2, 2, 2, 1, 2, 0, 1, 0, 1, 1, 0, 2, 0, 1, 0, 1, 1, 0, 0, 1, 2, 1, 1, 1, 0, 0, 2, 0, 2, 1, 0, 2, 2, 2, 1, 0, 2, 2, 0, 0, 1, 2, 2, 1, 0, 1, 0, 1, 2, 2, 2, 0, 1, 2, 2, 1, 1, 2, 1, 1, 2, 0, 2, 0, 2, 0, 0, 0, 0, 2, 1, 1, 2, 1, 0, 1, 0, 2, 1, 1, 0, 0, 2, 2, 2, 2, 0, 1, 1, 2, 1, 2, 2, 0, 1, 2, 2, 2, 0, 1, 0, 2, 2, 0, 2, 1, 1, 2, 1, 2, 1, 0, 0, 2, 1, 0, 0, 1, 2, 2, 1, 1, 1, 0, 1, 0, 2, 2, 0, 2, 2, 2, 0, 2, 2, 1, 0, 0, 0, 2, 1, 0, 0, 1, 1, 1, 2, 2, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 2, 2, 1, 0, 1, 0, 2, 0, 1, 2, 0, 1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 2, 1, 0, 2, 1, 1, 2, 0, 2, 1, 0, 0, 0, 1, 0, 2, 1, 2, 0, 1, 2, 1, 0, 2, 0, 2, 1, 0, 0, 1, 2, 0, 2, 2, 2, 0, 1, 0, 2, 0, 1, 0, 2, 1, 2, 1, 2, 2, 1, 1, 2, 0, 2, 2, 1, 0, 0, 2, 0, 2, 1, 0, 1},
 {1, 1, 1, 0, 2, 2, 0, 2, 0, 1, 0, 2, 1, 1, 0, 0, 1, 1, 1, 2, 0, 1, 1, 2, 0, 1, 1, 1, 2, 0, 2, 2, 2, 0, 2, 1, 1, 2, 1, 0, 2, 1, 0, 2, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 2, 0, 0, 0, 2, 1, 1, 0, 1, 2, 0, 1, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 2, 2, 0, 2, 0, 2, 1, 0, 2, 1, 0, 0, 1, 2, 2, 0, 0, 0, 0, 1, 0, 2, 2, 2, 1, 1, 0, 1, 0, 2, 1, 2, 2, 2, 1, 0, 2, 2, 0, 2, 0, 1, 2, 1, 0, 1, 0, 0, 1, 1, 0, 1, 2, 2, 2, 0, 0, 1, 0, 0, 1, 2, 1, 1, 1, 2, 0, 0, 0, 2, 1, 0, 2, 1, 2, 2, 1, 2, 1, 0, 0, 0, 2, 0, 0, 0, 2, 2, 1, 2, 2, 0, 0, 1, 2, 2, 1, 0, 0, 2, 1, 2, 2, 2, 0, 1, 1, 1, 1, 2, 0, 1, 1, 2, 2, 1, 0, 1, 2, 0, 2, 2, 1, 0, 1, 2, 1, 0, 1, 0, 1, 1, 2, 1, 1, 2, 2, 2, 1, 0, 2, 0, 0, 0, 1, 1, 2, 1, 0, 2, 0, 1, 1, 1, 2},
 {0, 2, 0, 2, 1, 2, 1, 1, 2, 1, 1, 2, 2, 2, 2, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 2, 2, 0, 1, 0, 2, 2, 1, 2, 2, 2, 2, 1, 2, 1, 1, 0, 0, 1, 0, 2, 0, 2, 0, 1, 2, 0, 0, 2, 2, 2, 1, 1, 0, 0, 2, 0, 2, 2, 2, 2, 1, 2, 1, 0, 2, 0, 2, 0, 2, 0, 2, 2, 0, 2, 2, 1, 2, 1, 2, 0, 0, 0, 0, 1, 0, 2, 1, 1, 2, 1, 0, 1, 0, 2, 0, 1, 0, 0, 2, 2, 2, 2, 2, 1, 1, 0, 1, 2, 2, 0, 0, 2, 2, 1, 0, 1, 2, 2, 1, 0, 2, 1, 1, 2, 1, 2, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 2, 0, 2, 0, 0, 1, 0, 0, 1, 0, 2, 1, 0, 2, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 1, 0, 2, 0, 0, 1, 2, 0, 1, 1, 2, 2, 0, 2, 2, 0, 0, 2, 2, 1, 2, 0, 0, 0, 1, 0, 2, 1, 0, 1, 2, 1, 1, 0, 2, 0, 0, 2, 1, 1, 0, 1, 1, 2, 0, 0, 1, 1, 1, 0, 0, 2, 2, 2, 2, 1, 1, 2, 2},
 {1, 2, 2, 0, 2, 2, 0, 1, 0, 0, 0, 2, 0, 0, 0, 2, 1, 0, 2, 2, 0, 0, 1, 2, 1, 0, 0, 1, 0, 1, 2, 2, 1, 2, 1, 0, 0, 1, 1, 2, 0, 0, 2, 2, 1, 0, 1, 2, 2, 2, 0, 2, 1, 1, 2, 1, 2, 1, 1, 0, 2, 1, 0, 0, 1, 2, 0, 1, 1, 0, 0, 1, 0, 2, 0, 0, 2, 0, 2, 0, 0, 2, 2, 0, 0, 0, 2, 1, 0, 0, 2, 0, 1, 1, 2, 1, 0, 1, 1, 0, 1, 2, 2, 0, 2, 2, 0, 0, 0, 1, 2, 2, 0, 0, 0, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 2, 2, 0, 1, 1, 2, 2, 2, 2, 2, 0, 2, 2, 2, 1, 1, 0, 0, 1, 0, 0, 2, 2, 2, 1, 2, 0, 0, 0, 1, 2, 2, 2, 0, 1, 2, 1, 1, 2, 2, 1, 1, 2, 0, 1, 0, 0, 1, 0, 2, 0, 2, 0, 1, 0, 0, 0, 2, 2, 2, 1, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 2, 0, 0, 0, 0, 0, 2, 2, 0, 2, 2, 1, 0, 0, 2, 2, 0, 0},
 {0, 1, 1, 1, 1, 2, 0, 1, 1, 1, 1, 1, 0, 1, 2, 0, 2, 1, 0, 0, 2, 0, 1, 0, 1, 2, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 2, 0, 0, 0, 1, 0, 2, 2, 1, 0, 0, 1, 1, 0, 2, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 2, 0, 2, 0, 2, 1, 2, 1, 1, 0, 1, 1, 2, 2, 2, 2, 0, 1, 0, 0, 2, 1, 1, 0, 1, 2, 1, 0, 1, 1, 1, 1, 0, 1, 1, 2, 2, 0, 1, 0, 2, 0, 0, 2, 1, 2, 2, 1, 2, 2, 0, 0, 1, 2, 0, 0, 0, 0, 2, 1, 2, 2, 0, 2, 1, 0, 2, 1, 2, 0, 2, 0, 2, 0, 0, 0, 2, 1, 1, 1, 2, 1, 0, 1, 2, 1, 1, 2, 1, 0, 2, 2, 1, 1, 0, 0, 0, 2, 0, 1, 1, 2, 1, 2, 2, 2, 0, 1, 2, 2, 0, 1, 0, 1, 1, 2, 0, 2, 2, 2, 1, 1, 0, 2, 2, 1, 0, 2, 2, 2, 1, 1, 1, 1, 1, 0, 1, 2, 2, 2, 2, 0, 0, 2, 0, 1, 2, 1, 0, 1, 1, 0, 0, 1, 0, 1, 2, 2, 0, 0, 2, 0, 0, 1, 1, 2, 2, 1, 0, 0, 0, 2, 1, 2, 1, 0, 1, 1, 2, 2, 1, 2},
 {2, 2, 2, 0, 2, 1, 0, 0, 0, 1, 0, 1, 0, 2, 0, 1, 2, 1, 0, 1, 2, 2, 2, 1, 0, 1, 2, 2, 1, 2, 1, 2, 1, 2, 1, 2, 0, 0, 2, 1, 2, 1, 2, 1, 1, 2, 0, 1, 2, 2, 1, 2, 0, 0, 2, 0, 0, 2, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 2, 2, 0, 2, 1, 0, 0, 0, 2, 2, 0, 0, 2, 0, 1, 2, 2, 2, 0, 1, 0, 0, 1, 0, 2, 1, 1, 2, 1, 0, 0, 0, 2, 0, 1, 0, 0, 2, 1, 2, 2, 0, 1, 1, 0, 1, 1, 2, 0, 2, 2, 2, 0, 0, 0, 2, 2, 1, 0, 2, 1, 1, 1, 2, 2, 1, 1, 0, 0, 1, 2, 1, 1, 0, 2, 1, 2, 0, 2, 1, 0, 1, 1, 0, 2, 1, 1, 2, 0, 2, 0, 0, 1, 0, 1, 0, 2, 1, 1, 0, 2, 0, 1, 2, 2, 0, 1, 1, 1, 2, 1, 0, 2, 2, 2, 2, 1, 1, 0, 2, 0, 1, 2, 0, 2, 2, 1, 1, 2, 1, 0, 0, 1, 0, 1, 2, 0, 0, 2, 1, 0, 0, 1, 1, 0, 2, 0, 1, 0, 1, 0, 1, 0, 1, 2, 1, 1, 1, 2, 1, 2, 1, 1, 1, 0, 2, 1, 0, 1, 2, 0, 2, 2, 1, 0},
 {0, 2, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 2, 2, 1, 0, 1, 0, 0, 2, 1, 1, 1, 1, 2, 2, 0, 1, 1, 1, 2, 0, 1, 1, 2, 2, 2, 1, 1, 2, 0, 2, 2, 1, 1, 2, 2, 0, 2, 1, 0, 1, 2, 0, 1, 2, 0, 2, 0, 2, 1, 0, 0, 0, 0, 1, 1, 2, 2, 0, 1, 2, 0, 1, 1, 2, 1, 2, 2, 0, 0, 0, 2, 2, 0, 1, 0, 2, 1, 1, 2, 2, 0, 2, 1, 2, 0, 1, 0, 1, 2, 0, 2, 2, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 2, 0, 1, 2, 0, 2, 1, 0, 2, 2, 0, 0, 0, 1, 2, 0, 0, 1, 0, 1, 1, 1, 2, 0, 2, 2, 0, 1, 0, 1, 1, 2, 1, 0, 0, 2, 1, 1, 0, 2, 0, 2, 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 2, 0, 0, 0, 1, 1, 1, 2, 0, 1, 2, 1, 1, 1, 1, 1, 2, 0, 0, 1, 0, 2, 0, 0, 1, 2, 2, 2, 0, 2, 2, 0, 2, 2, 2, 1, 1, 0, 0, 0, 0, 0, 2, 2, 2, 1, 2, 2, 0, 0, 2, 2, 2, 2, 0, 0, 2, 1, 0, 2, 2, 0, 1, 1, 0, 1, 0, 0, 1, 0, 2, 2, 0, 0, 2, 0, 0},
 {0, 2, 1, 0, 1, 0, 0, 0, 1, 2, 1, 0, 2, 2, 0, 2, 1, 2, 1, 2, 0, 1, 0, 0, 2, 2, 2, 1, 1, 0, 1, 0, 1, 2, 2, 2, 2, 1, 0, 2, 1, 1, 2, 1, 0, 2, 1, 0, 0, 1, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 2, 1, 0, 0, 0, 1, 0, 2, 1, 1, 0, 1, 2, 1, 0, 2, 0, 1, 1, 0, 1, 1, 2, 0, 2, 1, 2, 0, 0, 0, 2, 2, 1, 2, 2, 1, 2, 1, 2, 2, 1, 0, 0, 0, 0, 2, 1, 0, 0, 1, 1, 2, 0, 2, 1, 0, 1, 0, 1, 2, 2, 1, 2, 0, 2, 2, 1, 1, 2, 0, 0, 1, 1, 0, 1, 2, 0, 2, 2, 2, 1, 0, 0, 1, 0, 1, 0, 2, 2, 1, 1, 0, 0, 1, 2, 2, 1, 1, 2, 1, 2, 0, 2, 2, 0, 2, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 2, 1, 1, 2, 2, 2, 1, 0, 2, 0, 1, 0, 1, 1, 2, 1, 0, 2, 1, 1, 1, 0, 2, 0, 2, 0, 0, 1, 2, 2, 1, 2, 2, 1, 0, 2, 2, 2, 0, 0, 0, 0, 1, 0, 1, 2, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 2, 2, 0, 2},
 {1, 0, 1, 2, 1, 1, 0, 0, 2, 0, 2, 1, 1, 0, 1, 2, 1, 0, 2, 2, 1, 1, 0, 1, 1, 2, 0, 1, 1, 2, 1, 0, 0, 2, 2, 0, 2, 2, 0, 2, 1, 1, 2, 0, 0, 0, 0, 0, 2, 1, 0, 2, 2, 1, 0, 0, 2, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 2, 0, 2, 1, 0, 0, 2, 2, 2, 0, 2, 2, 0, 1, 1, 2, 2, 1, 0, 0, 0, 2, 2, 2, 1, 0, 1, 1, 2, 2, 2, 2, 2, 1, 2, 0, 2, 1, 1, 0, 0, 2, 0, 1, 1, 2, 1, 1, 2, 1, 0, 1, 2, 2, 0, 0, 0, 0, 2, 2, 1, 2, 2, 1, 1, 0, 2, 2, 1, 0, 0, 0, 2, 1, 1, 1, 1, 1, 1, 2, 2, 1, 1, 2, 0, 0, 0, 1, 1, 0, 2, 0, 2, 2, 1, 1, 1, 0, 1, 2, 2, 0, 1, 2, 2, 2, 0, 1, 2, 2, 2, 0, 2, 1, 1, 2, 0, 2, 1, 1, 0, 2, 1, 0, 2, 1, 2, 1, 1, 1, 0, 0, 0, 0, 2, 2, 0, 2, 2, 2, 2, 0, 2, 2, 0, 0, 0, 2, 0, 1, 0, 0, 0, 1, 1, 2, 0, 1, 1, 0, 2, 1, 1, 2, 2, 0, 2, 0, 1},
 {0, 1, 0, 1, 2, 0, 1, 1, 1, 1, 2, 1, 1, 0, 0, 2, 1, 0, 1, 0, 0, 1, 2, 1, 1, 0, 2, 2, 0, 0, 2, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 2, 0, 1, 2, 0, 2, 1, 2, 2, 2, 1, 0, 0, 1, 2, 2, 0, 1, 2, 1, 1, 0, 2, 2, 2, 2, 0, 1, 0, 1, 1, 1, 2, 0, 1, 2, 1, 1, 0, 1, 1, 2, 0, 0, 1, 0, 1, 0, 0, 2, 2, 2, 2, 0, 1, 2, 0, 1, 2, 2, 0, 1, 2, 0, 0, 0, 0, 2, 2, 2, 0, 0, 2, 1, 0, 2, 2, 2, 1, 1, 0, 1, 0, 0, 1, 2, 2, 2, 1, 0, 2, 0, 0, 2, 2, 1, 2, 1, 0, 2, 0, 0, 2, 1, 0, 2, 2, 0, 2, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 2, 0, 1, 0, 0, 0, 0, 2, 2, 0, 2, 1, 0, 2, 0, 2, 2, 0, 0, 2, 0, 0, 2, 2, 0, 0, 1, 0, 0, 0, 0, 2, 0, 1, 2, 0, 0, 2, 0, 2, 0, 1, 0, 0, 2, 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 2, 2, 0, 2, 0, 2, 1, 1, 2, 1, 2, 0, 1, 2, 2, 1},
 {0, 0, 1, 1, 0, 0, 2, 0, 1, 1, 0, 1, 0, 2, 1, 0, 1, 2, 0, 0, 2, 2, 0, 0, 2, 1, 0, 2, 0, 2, 0, 1, 0, 1, 0, 0, 2, 2, 1, 1, 1, 1, 2, 0, 1, 2, 1, 2, 2, 0, 1, 2, 0, 0, 1, 1, 0, 2, 2, 0, 0, 2, 2, 1, 0, 1, 1, 0, 1, 0, 2, 1, 1, 2, 0, 0, 0, 2, 2, 0, 1, 0, 2, 2, 1, 2, 2, 0, 2, 1, 2, 1, 1, 0, 0, 2, 0, 2, 2, 2, 0, 1, 2, 1, 0, 2, 0, 2, 1, 2, 0, 1, 2, 0, 2, 2, 2, 2, 1, 0, 0, 0, 1, 0, 2, 0, 2, 1, 1, 2, 1, 0, 2, 2, 2, 2, 1, 0, 0, 2, 0, 1, 2, 0, 2, 1, 1, 1, 0, 1, 0, 0, 1, 2, 1, 2, 2, 0, 2, 0, 0, 2, 1, 1, 0, 2, 0, 1, 0, 0, 1, 1, 1, 1, 2, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 2, 0, 1, 0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 2, 2, 1, 1, 0, 2, 0, 0, 2, 1, 1, 2, 1, 1},
 {2, 0, 0, 1, 1, 0, 0, 0, 0, 2, 2, 2, 1, 0, 2, 2, 0, 2, 2, 2, 2, 1, 0, 1, 0, 0, 0, 2, 0, 2, 1, 2, 2, 0, 2, 2, 0, 2, 2, 2, 0, 2, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 1, 0, 0, 2, 1, 0, 2, 2, 1, 2, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 2, 0, 2, 0, 1, 0, 0, 2, 2, 2, 2, 1, 1, 1, 0, 1, 2, 2, 0, 2, 2, 2, 2, 0, 1, 2, 2, 0, 0, 2, 0, 1, 2, 0, 2, 2, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 2, 2, 2, 0, 0, 1, 0, 1, 1, 2, 1, 1, 1, 2, 0, 1, 0, 2, 0, 0, 2, 1, 2, 0, 1, 2, 2, 0, 0, 1, 2, 1, 0, 0, 2, 2, 1, 2, 2, 1, 2, 1, 1, 2, 1, 0, 0, 0, 0, 2, 0, 0, 0, 2, 1, 2, 0, 2, 0, 0, 1, 2, 1, 2, 1, 1, 1, 0, 2, 2, 1, 1, 2, 0, 2, 2, 1, 1, 1, 2, 0, 2, 1, 0, 1, 2, 2, 1, 2, 1, 2, 0, 2, 1, 2, 0, 0, 2, 1, 1, 1, 2, 2, 1, 2, 0, 1, 1, 2, 1, 1, 0, 0, 1, 0, 2},
 {2, 0, 0, 1, 2, 0, 0, 2, 1, 0, 1, 2, 2, 0, 2, 0, 1, 0, 2, 1, 2, 2, 0, 1, 1, 1, 2, 0, 2, 0, 2, 2, 2, 1, 1, 2, 1, 1, 2, 0, 2, 2, 2, 0, 0, 0, 0, 2, 1, 0, 2, 1, 1, 1, 0, 2, 1, 0, 0, 0, 1, 2, 2, 1, 0, 0, 1, 2, 1, 2, 2, 0, 1, 1, 0, 2, 1, 1, 0, 2, 2, 2, 0, 1, 0, 1, 1, 1, 1, 2, 1, 2, 1, 1, 0, 1, 0, 1, 0, 1, 2, 0, 1, 0, 2, 1, 2, 1, 1, 0, 0, 1, 2, 0, 2, 2, 0, 1, 2, 0, 2, 0, 1, 0, 0, 2, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 2, 1, 1, 0, 2, 0, 2, 0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 2, 1, 0, 0, 1, 1, 0, 2, 0, 0, 2, 1, 0, 1, 0, 1, 2, 0, 0, 1, 0, 2, 2, 1, 1, 0, 2, 2, 0, 2, 1, 1, 2, 1, 1, 1, 0, 0, 2, 1, 0, 0, 0, 2, 2, 2, 1, 1, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 1, 2, 1, 0, 0, 0, 2, 1, 2, 1, 1, 2, 1, 2, 2, 1, 2, 2, 0, 0, 0, 1, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0},
 {2, 0, 2, 1, 1, 2, 2, 2, 1, 0, 2, 2, 1, 0, 1, 1, 2, 1, 0, 1, 1, 1, 2, 0, 2, 0, 2, 2, 0, 1, 1, 2, 1, 1, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 0, 2, 2, 1, 1, 1, 2, 2, 0, 0, 0, 1, 2, 2, 1, 1, 2, 1, 1, 1, 2, 2, 0, 2, 0, 0, 0, 2, 1, 1, 2, 0, 1, 0, 1, 2, 1, 1, 0, 2, 0, 1, 1, 1, 1, 0, 1, 1, 2, 1, 2, 1, 0, 2, 0, 0, 2, 0, 1, 2, 2, 0, 2, 0, 0, 0, 1, 0, 2, 2, 0, 1, 0, 1, 1, 0, 2, 1, 0, 2, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 2, 0, 0, 0, 2, 0, 1, 1, 2, 2, 2, 1, 2, 0, 1, 2, 2, 1, 1, 2, 0, 1, 0, 0, 2, 0, 2, 0, 2, 0, 1, 0, 1, 0, 2, 1, 2, 1, 1, 1, 1, 2, 2, 0, 2, 2, 0, 2, 0, 1, 1, 2, 0, 0, 0, 0, 1, 1, 2, 2, 2, 2, 1, 0, 1, 1, 2, 1, 1, 0, 2, 1, 2, 0, 2, 0, 0, 1, 1, 0, 2, 1, 1, 1, 0, 2, 1, 0, 1, 0, 1, 2, 2, 1, 0, 0, 2, 2, 1, 1, 2, 0, 1, 1, 1, 2, 1},
 {2, 0, 2, 0, 2, 1, 1, 0, 1, 1, 1, 1, 2, 2, 1, 1, 0, 0, 1, 0, 1, 1, 0, 2, 1, 2, 0, 0, 1, 0, 0, 1, 0, 2, 1, 2, 2, 0, 0, 0, 0, 2, 0, 2, 0, 2, 1, 1, 0, 2, 0, 2, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 0, 0, 2, 2, 1, 1, 1, 0, 1, 1, 0, 2, 1, 2, 2, 2, 0, 0, 0, 1, 0, 2, 0, 1, 1, 1, 1, 1, 0, 2, 2, 1, 2, 1, 0, 0, 2, 1, 1, 1, 0, 2, 2, 1, 1, 1, 1, 2, 2, 1, 1, 1, 2, 2, 0, 1, 1, 0, 2, 2, 1, 1, 2, 2, 2, 0, 1, 1, 1, 2, 0, 1, 1, 1, 2, 2, 1, 1, 2, 0, 2, 1, 1, 1, 0, 2, 0, 2, 1, 2, 1, 2, 2, 1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 1, 0, 0, 2, 1, 1, 2, 0, 1, 0, 0, 1, 1, 1, 0, 2, 0, 1, 0, 0, 1, 1, 2, 1, 2, 1, 1, 0, 0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 2, 0, 2, 0, 1, 1, 0, 2, 1, 0, 2, 1, 1, 2, 0, 1, 0, 0, 0},
 {0, 1, 0, 2, 0, 1, 0, 2, 0, 1, 0, 2, 2, 1, 1, 2, 2, 1, 1, 2, 1, 1, 2, 0, 1, 0, 2, 0, 0, 0, 0, 2, 0, 1, 2, 2, 0, 1, 0, 2, 0, 1, 0, 2, 2, 2, 1, 2, 2, 1, 1, 2, 1, 2, 2, 0, 0, 0, 2, 0, 0, 1, 0, 2, 1, 1, 2, 0, 0, 2, 0, 2, 0, 1, 0, 2, 2, 0, 0, 2, 1, 1, 1, 2, 1, 0, 1, 0, 1, 1, 2, 1, 0, 2, 2, 2, 1, 0, 2, 0, 2, 0, 1, 2, 2, 1, 0, 2, 2, 1, 1, 0, 2, 0, 1, 0, 1, 1, 2, 1, 1, 2, 1, 1, 1, 0, 2, 0, 0, 0, 0, 0, 2, 2, 1, 2, 0, 1, 0, 0, 2, 2, 1, 0, 1, 0, 1, 0, 1, 2, 1, 1, 2, 2, 1, 2, 1, 1, 1, 0, 0, 1, 0, 0, 2, 0, 2, 2, 2, 0, 0, 0, 1, 0, 2, 0, 2, 1, 1, 1, 1, 0, 2, 2, 2, 2, 1, 2, 0, 2, 1, 1, 2, 0, 2, 0, 1, 1, 2, 1, 0, 2, 1, 1, 1, 2, 2, 0, 2, 0, 0, 1, 2, 1, 1, 2, 0, 1, 0, 2, 2, 1, 0, 0, 2, 0, 1, 2, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 2, 0, 0, 2, 0},
 {2, 1, 2, 2, 2, 0, 0, 0, 2, 2, 2, 0, 1, 1, 1, 1, 2, 2, 2, 1, 2, 2, 1, 0, 1, 1, 1, 2, 0, 0, 0, 1, 2, 0, 1, 1, 2, 2, 1, 1, 2, 0, 0, 2, 2, 1, 0, 2, 0, 2, 2, 0, 2, 1, 1, 0, 2, 2, 0, 0, 0, 2, 1, 1, 1, 1, 0, 1, 1, 2, 1, 1, 2, 0, 2, 0, 0, 2, 0, 0, 0, 2, 1, 1, 0, 0, 0, 0, 1, 2, 1, 1, 1, 2, 2, 0, 1, 2, 1, 0, 2, 1, 1, 2, 2, 0, 1, 2, 0, 0, 1, 0, 1, 2, 2, 0, 0, 2, 2, 0, 1, 1, 2, 2, 1, 0, 2, 0, 2, 2, 2, 1, 0, 1, 0, 2, 2, 0, 2, 2, 1, 2, 2, 2, 1, 0, 0, 0, 1, 0, 0, 1, 2, 1, 1, 2, 1, 0, 0, 0, 2, 1, 0, 0, 0, 2, 1, 2, 2, 1, 0, 1, 2, 2, 1, 2, 0, 0, 1, 2, 1, 2, 0, 0, 1, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 1, 2, 2, 2, 1, 1, 1, 0, 2, 0, 0, 1, 2, 2, 2, 2, 1, 2, 0, 2, 2, 2, 1, 0, 2, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 2, 0, 1, 1, 1, 1, 0, 0, 2, 1, 0, 2, 1},
 {0, 2, 2, 1, 1, 0, 0, 0, 0, 0, 1, 1, 2, 1, 2, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2, 1, 2, 1, 2, 2, 0, 1, 2, 0, 2, 2, 1, 0, 2, 2, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 2, 0, 1, 0, 0, 0, 2, 1, 1, 0, 0, 1, 0, 2, 2, 1, 1, 1, 2, 0, 0, 2, 1, 1, 2, 2, 1, 2, 2, 0, 1, 1, 0, 1, 0, 0, 0, 2, 2, 2, 0, 0, 2, 0, 2, 2, 2, 2, 1, 1, 0, 0, 2, 0, 2, 0, 2, 2, 1, 2, 1, 0, 2, 1, 2, 0, 1, 0, 2, 2, 0, 0, 2, 1, 0, 1, 2, 1, 0, 1, 0, 1, 0, 2, 1, 1, 2, 2, 2, 1, 2, 2, 0, 1, 0, 1, 1, 2, 0, 0, 2, 2, 1, 1, 0, 2, 2, 2, 0, 2, 1, 2, 1, 1, 1, 2, 1, 0, 2, 2, 2, 0, 2, 1, 0, 2, 0, 1, 2, 1, 0, 2, 0, 0, 2, 1, 0, 1, 2, 0, 2, 0, 0, 1, 0, 2, 1, 0, 1, 1, 0, 2, 0, 2, 0, 0, 2, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 2, 2, 2, 0, 1, 1, 2, 0, 2, 2, 2, 1, 2, 2, 2, 2, 1, 0, 2, 2, 0, 0, 1, 0, 2, 1},
 {0, 1, 0, 1, 2, 0, 2, 0, 0, 2, 2, 1, 1, 0, 1, 1, 0, 0, 2, 1, 2, 1, 0, 0, 0, 2, 1, 1, 2, 2, 2, 1, 2, 2, 1, 1, 0, 1, 1, 2, 0, 0, 0, 2, 1, 0, 0, 2, 2, 2, 1, 2, 1, 0, 1, 1, 2, 2, 2, 0, 2, 2, 2, 0, 2, 1, 1, 1, 0, 0, 2, 1, 0, 2, 1, 2, 2, 2, 1, 1, 0, 0, 0, 2, 0, 1, 2, 2, 1, 2, 2, 2, 0, 1, 0, 2, 0, 0, 0, 1, 1, 2, 1, 2, 2, 0, 1, 1, 1, 2, 0, 1, 0, 2, 2, 2, 1, 1, 2, 0, 1, 2, 1, 2, 2, 2, 0, 2, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 2, 1, 0, 0, 0, 0, 0, 2, 2, 0, 0, 1, 2, 0, 0, 2, 2, 0, 1, 2, 2, 0, 2, 0, 2, 0, 2, 0, 2, 2, 0, 1, 2, 1, 2, 1, 2, 0, 0, 2, 0, 1, 1, 2, 1, 1, 2, 0, 0, 1, 2, 2, 0, 0, 0, 2, 2, 2, 2, 2, 2, 1, 1, 2, 2, 2, 0, 0, 0, 2, 2, 0, 1, 1, 1, 1, 1, 2, 2, 0, 2, 2, 1, 0, 0, 1, 1, 2, 0, 0, 1, 1, 1, 0, 1, 2, 2, 2, 2, 1, 1, 2, 0, 1, 2},
 {1, 0, 2, 2, 0, 2, 0, 0, 1, 2, 0, 1, 0, 0, 1, 0, 2, 2, 0, 0, 1, 0, 0, 0, 2, 1, 0, 1, 2, 0, 0, 2, 2, 1, 0, 2, 1, 0, 2, 0, 2, 1, 1, 0, 0, 0, 0, 2, 2, 2, 1, 1, 2, 2, 0, 2, 2, 2, 2, 2, 0, 1, 2, 0, 0, 2, 0, 0, 1, 2, 0, 0, 2, 0, 0, 0, 2, 2, 0, 2, 0, 0, 0, 1, 2, 2, 0, 0, 1, 0, 1, 1, 2, 2, 2, 1, 2, 0, 1, 0, 2, 1, 1, 2, 0, 1, 0, 1, 2, 0, 1, 0, 2, 0, 1, 1, 1, 0, 0, 1, 2, 2, 1, 2, 1, 2, 2, 0, 2, 2, 0, 0, 2, 1, 0, 2, 0, 0, 0, 1, 0, 1, 0, 0, 2, 0, 1, 1, 0, 1, 2, 0, 1, 0, 1, 2, 0, 0, 1, 0, 0, 1, 1, 1, 0, 2, 2, 0, 0, 0, 1, 1, 2, 1, 1, 0, 1, 1, 1, 1, 2, 0, 0, 1, 0, 0, 1, 0, 1, 2, 2, 2, 0, 0, 0, 0, 1, 1, 2, 1, 1, 1, 1, 0, 1, 1, 2, 0, 0, 2, 0, 2, 0, 0, 2, 2, 2, 0, 0, 2, 1, 0, 0, 2, 2, 1, 1, 0, 1, 0, 1, 1, 2, 1, 2, 1, 0, 2, 1, 0, 2, 0, 1},
 {2, 2, 0, 0, 0, 0, 2, 1, 0, 2, 2, 1, 1, 0, 2, 1, 0, 0, 1, 1, 2, 1, 1, 0, 0, 1, 0, 1, 2, 0, 0, 1, 2, 0, 0, 1, 1, 0, 2, 2, 2, 0, 2, 2, 1, 0, 1, 1, 2, 1, 0, 0, 1, 1, 2, 0, 2, 0, 2, 1, 0, 1, 2, 2, 1, 1, 2, 2, 0, 2, 1, 2, 0, 2, 0, 1, 2, 0, 2, 2, 1, 1, 1, 1, 0, 0, 1, 0, 1, 2, 2, 0, 2, 2, 0, 0, 1, 1, 2, 2, 0, 0, 0, 1, 2, 1, 2, 1, 2, 1, 1, 1, 2, 1, 1, 2, 1, 2, 0, 2, 1, 0, 0, 0, 0, 1, 1, 1, 2, 0, 1, 2, 0, 1, 1, 1, 1, 2, 0, 0, 0, 0, 2, 1, 0, 1, 2, 2, 1, 0, 2, 1, 0, 2, 1, 2, 0, 1, 0, 0, 0, 0, 0, 2, 1, 0, 1, 0, 2, 0, 0, 2, 1, 0, 2, 2, 2, 2, 0, 0, 1, 0, 0, 1, 2, 0, 1, 1, 2, 0, 0, 0, 2, 0, 0, 2, 2, 2, 2, 1, 2, 0, 0, 0, 2, 2, 0, 2, 0, 1, 2, 1, 2, 2, 0, 0, 1, 1, 0, 1, 1, 0, 2, 1, 2, 1, 0, 0, 0, 0, 1, 0, 2, 2, 2, 1, 2, 0, 1, 0, 2, 1, 2},
 {2, 0, 1, 0, 1, 2, 0, 2, 0, 2, 2, 1, 1, 1, 0, 1, 1, 2, 0, 1, 2, 2, 2, 0, 0, 2, 2, 0, 0, 2, 1, 1, 1, 0, 2, 0, 1, 0, 1, 1, 2, 2, 1, 2, 1, 1, 1, 0, 2, 1, 0, 0, 2, 0, 2, 2, 1, 0, 0, 1, 1, 0, 2, 0, 1, 1, 1, 0, 1, 0, 1, 2, 1, 2, 1, 2, 0, 2, 1, 1, 1, 1, 2, 1, 1, 1, 2, 1, 2, 0, 1, 0, 0, 2, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 2, 0, 0, 0, 2, 1, 0, 0, 1, 2, 0, 1, 2, 1, 0, 1, 0, 2, 0, 0, 0, 1, 2, 2, 2, 2, 2, 0, 1, 1, 2, 2, 1, 0, 0, 1, 2, 2, 2, 1, 0, 1, 1, 0, 2, 2, 1, 2, 1, 2, 0, 0, 1, 1, 1, 0, 2, 1, 1, 2, 2, 1, 1, 2, 1, 0, 1, 0, 1, 0, 2, 0, 0, 2, 2, 2, 1, 2, 2, 2, 0, 0, 2, 2, 2, 0, 0, 1, 1, 1, 0, 2, 2, 1, 1, 2, 1, 1, 2, 1, 1, 1, 2, 0, 0, 0, 0, 0, 0, 2, 1, 2, 2, 1, 0, 0, 0, 2, 1, 2, 0, 0, 1, 1, 2, 2, 1, 2, 1, 2, 2, 1, 2, 1, 0, 0, 2, 1, 0},
 {0, 0, 2, 2, 1, 1, 1, 0, 1, 2, 2, 2, 1, 2, 2, 2, 0, 1, 2, 1, 2, 0, 0, 1, 1, 2, 0, 1, 1, 1, 2, 2, 1, 2, 2, 0, 2, 1, 1, 1, 0, 0, 0, 2, 0, 2, 1, 2, 2, 2, 2, 2, 0, 2, 2, 2, 0, 1, 0, 0, 1, 0, 0, 2, 1, 2, 1, 0, 0, 0, 0, 1, 1, 2, 2, 2, 1, 2, 0, 1, 1, 2, 1, 1, 2, 0, 1, 0, 2, 2, 0, 0, 0, 2, 0, 1, 2, 1, 0, 1, 1, 2, 0, 1, 0, 1, 2, 2, 0, 2, 2, 0, 1, 1, 1, 2, 2, 0, 0, 0, 2, 2, 1, 1, 1, 2, 1, 1, 2, 2, 1, 2, 2, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 2, 1, 0, 0, 2, 0, 1, 1, 2, 0, 2, 1, 1, 0, 1, 2, 2, 2, 1, 2, 1, 1, 0, 1, 2, 1, 2, 0, 2, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 2, 0, 0, 0, 2, 0, 2, 1, 2, 1, 0, 1, 2, 0, 2, 2, 2, 2, 2, 2, 1, 0, 1, 0, 2, 0, 0, 0, 2, 1, 2, 2, 2, 2, 0, 1, 2, 1, 2, 0, 1, 0, 1, 2, 0, 1},
 {1, 1, 0, 1, 1, 1, 0, 0, 2, 1, 2, 0, 0, 1, 2, 2, 1, 1, 2, 1, 2, 2, 2, 2, 0, 2, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 2, 0, 1, 2, 1, 2, 1, 2, 2, 2, 1, 0, 1, 1, 2, 1, 0, 1, 2, 1, 2, 0, 2, 0, 2, 2, 1, 1, 1, 1, 1, 1, 2, 0, 1, 2, 2, 0, 0, 0, 1, 2, 0, 0, 2, 2, 1, 1, 1, 2, 0, 2, 0, 2, 1, 2, 2, 1, 2, 1, 1, 2, 2, 2, 0, 0, 0, 2, 0, 0, 1, 1, 1, 1, 1, 2, 0, 0, 2, 1, 1, 0, 0, 1, 2, 2, 0, 1, 1, 1, 2, 0, 2, 2, 2, 2, 2, 1, 1, 2, 1, 0, 2, 0, 0, 2, 2, 0, 0, 2, 0, 2, 0, 0, 2, 0, 1, 0, 0, 2, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 2, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 2, 2, 0, 0, 1, 1, 0, 0, 1, 2, 2, 1, 2, 1, 0, 2, 0, 2, 2, 0, 0, 2, 2, 0, 2, 2, 0, 0, 1, 0, 2, 0, 0, 0, 0, 1, 2, 0, 2, 2, 0, 1, 0, 1, 2, 0, 1, 0, 0, 2, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 2, 2, 2, 0},
};
/*
static const int sbox_lookup[27] = {6, 25, 17, 5, 15, 10, 4, 20, 24, 
                                    0, 1, 2, 9, 22, 26, 18, 16, 14,
                                    3, 13, 23, 7, 11, 12, 8, 21, 19};
*/
static const int shift_rows_param[3] = {0, 1, 2};

static const int shift_lanes_param[27] = {19, 13, 21, 10, 24, 15, 2, 9, 3, 
                                          14, 0, 6, 5, 1, 25, 22, 23, 20, 
                                          7, 17, 26, 12, 8, 18, 16, 11, 4};

static long get_microtime(){
    struct timeval t;
    gettimeofday(&t, NULL);
    return t.tv_sec * (int)1e6 + t.tv_usec;
}

void PrintTroikaSlice(uint8_t *state, int slice)
{
	fprintf(stderr, "#### Slice %i ####\n", slice);
	for (int row = 0; row < ROWS; ++row) {
		for (int column = 0; column < COLUMNS; ++column) {
			fprintf(stderr, "%i ", state[slice*SLICES + row*COLUMNS + column]);
		}
		fprintf(stderr, "\n");
	}
	fprintf(stderr, "------------------\n");
	for (int i = 0; i < COLUMNS; i++) {
		fprintf(stderr, "%i ", (state[slice*SLICES + 0*COLUMNS + i] + state[slice*SLICES + 1*COLUMNS + i] + state[slice*SLICES + 2*COLUMNS + i]) % 3);
	}
	fprintf(stderr, "\n");
}

void PrintTroikaState(uint8_t *state)
{
    //fprintf(stderr, "Troika State:\n");

    for (int slice = 0; slice < SLICES; ++slice) {
		PrintTroikaSlice(state, slice);
    }
}

#ifdef DEBUG
#define inline
#endif

inline uint8_t simd_exportValue(int nr, Trit* t) {
#if SIMD_SIZE!=128 && SIMD_SIZE != 256
	return ((t->lo >> nr) & 0x1) | ((((t->lo ^ t->hi) >> nr) & 0x1) << 1);
#elif SIMD_SIZE == 128
	return (uint8_t) (_mm_movepi64_pi64(((t->lo >> nr) & 0x1) | ((((t->lo ^ t->hi) >> nr) & 0x1) << 1))[0] & 0xff);
#else
	uint64_t tmpLo[4];
	uint64_t tmpHi[4];
	_mm256_store_si256((__m256i*) tmpLo, t->lo);
	_mm256_store_si256((__m256i*) tmpHi, t->hi ^ t->lo);

	uint8_t bitLo = (uint8_t) ((tmpLo[nr / 64] >> (nr % 64)) & 0x1);
	uint8_t bitHi = (uint8_t) ((tmpHi[nr / 64] >> (nr % 64)) & 0x1);
	return bitLo | (bitHi << 1);
#endif
}

void simd_exportState(int nr, Trit* state, uint8_t* trits) {
	for (int i=0;i<729;i++) {
		*trits++ = simd_exportValue(nr, state++);
	}
}

void printState(int nr, Trit* state, int len) {
	uint8_t trits[729];
	simd_exportState(nr, state, trits);
	for (int i = 0; i < len; i++) {
		if (!(i % 27)) {
			printf("\n");
		}
		if (!(i % 9)) {
			printf(" ");
		}
		printf("%d", trits[i]);
	}
	printf("\n");
}

static inline void simd_expandTrit(uint8_t t, Trit* dst) {
#if SIMD_SIZE!=128 && SIMD_SIZE != 256
	dst->lo = (t & 0x1) ? ~0ul : 0ul;
	dst->hi = (t & 0x2) ? ~0ul : 0ul;
	dst->hi = dst->lo ^ dst->hi;
#elif SIMD_SIZE == 128
	dst->lo = (t & 0x1) ? _mm_set1_epi32(0xffffffff) : _mm_set1_epi32(0x00000000);
	dst->hi = (t & 0x2) ? _mm_set1_epi32(0xffffffff) : _mm_set1_epi32(0x00000000);
	dst->hi = dst->lo ^ dst->hi;
#else
	dst->lo = (t & 0x1) ? _mm256_set1_epi32(0xffffffff) : _mm256_set1_epi32(0x00000000);
	dst->hi = (t & 0x2) ? _mm256_set1_epi32(0xffffffff) : _mm256_set1_epi32(0x00000000);
	dst->hi = dst->lo ^ dst->hi;
#endif
}

static inline void simd_set_zero(Trit* a) {
#if SIMD_SIZE != 128 && SIMD_SIZE != 256
	a->lo = 0;
	a->hi = 0;
#elif SIMD_SIZE == 128
	a->lo = _mm_set1_epi32(0u);
	a->hi = _mm_set1_epi32(0u);
#else
	a->lo = _mm256_set1_epi32(0u);
	a->hi = _mm256_set1_epi32(0u);
#endif
}

static inline Trit* simd_add_mod3(Trit* a, Trit* b, Trit* c) {
	Trit tmp;
	tmp.hi = ((a->hi ^ b->hi)) | ((a->hi ^ a->lo ^ b->lo));
	tmp.lo = ((b->lo & ~a->hi)) | ((a->lo ^ b->hi) & (a->hi & ~b->lo));
	c->hi = tmp.hi;
	c->lo = tmp.lo;
	return c;
}

static inline void simd_sbox(Trit* a, Trit* b, Trit* c) {
	Trit d2, d1, d0;
	d2.hi = ((b->hi & c->hi)) | ((c->hi & ~a->lo)) | ((a->lo ^ c->hi) & (b->hi));
	d2.lo = ((a->lo ^ b->lo) & (b->hi & c->hi)) | ((c->hi ^ c->lo) & (~a->hi & ~b->hi)) | ((a->lo ^ b->hi ^ b->lo ^ c->hi) & (a->hi & c->lo)) | ((a->lo ^ c->hi) & (b->lo));
	d1.hi = (~(a->hi ^ b->lo ^ c->lo) & (~a->lo)) | ((a->hi ^ b->lo ^ c->hi ^ c->lo) & (~a->lo)) | ((b->hi ^ c->hi) & (~a->lo)) | (~(a->lo ^ c->hi) & (b->hi));
	d1.lo = ((a->hi ^ a->lo) & (~b->hi)) | ((a->hi ^ b->hi) & (~a->lo & ~c->hi)) | ((a->lo ^ b->lo ^ c->lo) & (a->hi & b->hi & c->hi));
	d0.hi = ((a->hi ^ b->lo ^ c->lo) & (c->hi)) | ((a->hi ^ a->lo ^ b->lo ^ c->lo) & (c->hi)) | ((b->hi ^ c->hi) & (~a->lo));
	d0.lo = ((a->lo & c->lo)) | (~(a->hi ^ b->lo ^ c->hi) & (b->hi & ~a->lo & ~c->lo)) | ((c->lo & ~b->hi));
    *a = d2;
    *b = d1;
    *c = d0;
}


void SubTrytes(Trit *state)
{
    for (int i=0;i<729;i+=9) {
    	simd_sbox(&state[i], &state[i+1], &state[i+2]);
    	simd_sbox(&state[i+3], &state[i+4], &state[i+5]);
    	simd_sbox(&state[i+6], &state[i+7], &state[i+8]);
    }
}

void ShiftRowsAndLanes(Trit *state)
{
    Trit newstate[729];
    for (int i=0;i<729;i++) {
		newstate[i] = state[perm[i]];
    }
    memcpy(state, newstate, sizeof(newstate));
}



void AddColumnParity(Trit *state)
{
    int slice,  col;

    Trit parity[SLICES * COLUMNS];

    int pIdx = 0;
    int sIdx = 0;
    for (slice = 0;slice<SLICES;slice++) {
    	for (col=0;col<COLUMNS;col++, pIdx++, sIdx++) {
    		Trit col_sum_mod3;
    		col_sum_mod3 = state[sIdx];
    		simd_add_mod3(&state[sIdx + 9], &col_sum_mod3, &col_sum_mod3);
    		simd_add_mod3(&state[sIdx + 18], &col_sum_mod3, &col_sum_mod3);
    		parity[pIdx] = col_sum_mod3;
    	}
    	sIdx += 18;
    }

    pIdx = 0;
    sIdx = 0;
    // Add parity
    for (slice = 0; slice < SLICES; ++slice) {
		for (col = 0; col < COLUMNS; ++col, sIdx++, pIdx++) {
			simd_add_mod3(&state[sIdx], &parity[plutLeft[pIdx]], &state[sIdx]);
			simd_add_mod3(&state[sIdx], &parity[plutRight[pIdx]], &state[sIdx]);
			simd_add_mod3(&state[sIdx+9], &parity[plutLeft[pIdx]], &state[sIdx+9]);
			simd_add_mod3(&state[sIdx+9], &parity[plutRight[pIdx]], &state[sIdx+9]);
			simd_add_mod3(&state[sIdx+18], &parity[plutLeft[pIdx]], &state[sIdx+18]);
			simd_add_mod3(&state[sIdx+18], &parity[plutRight[pIdx]], &state[sIdx+18]);
		}
		sIdx+=18;
    }
}

void AddRoundConstant(Trit *state, int round)
{
    int slice, col, idx;
    for (slice = 0; slice < SLICES; ++slice) {
        for (col = 0; col < COLUMNS; ++col) {
            idx = SLICESIZE*slice + col;
			simd_add_mod3(&state[idx], &simd_round_constants[round][slice*COLUMNS + col], &state[idx]);
        }
    }
}


void initConstants() {
	uint16_t tmp[729];
    for (int slice = 0; slice < SLICES; ++slice) {
        for (int row = 0; row < ROWS; ++row) {
            for (int col = 0; col < COLUMNS; ++col) {
                int old_idx = SLICESIZE*slice + COLUMNS*row + col;
                int new_idx = SLICESIZE*slice + COLUMNS*row +
                          (col + 3*shift_rows_param[row]) % COLUMNS;
                tmp[new_idx] = old_idx;
            }
        }
    }

	for (int slice = 0; slice < SLICES; ++slice) {
		for (int row = 0; row < ROWS; ++row) {
			for (int col = 0; col < COLUMNS; ++col) {
				int old_idx = SLICESIZE*slice + COLUMNS*row + col;
				int new_slice = (slice + shift_lanes_param[col + COLUMNS*row]) % SLICES;
				int new_idx = SLICESIZE*(new_slice) + COLUMNS*row + col;
				perm[new_idx] = tmp[old_idx];
			}
		}
	}

    for (int slice = 0; slice < SLICES; ++slice) {
        for (int row = 0; row < ROWS; ++row) {
            for (int col = 0; col < COLUMNS; ++col) {
                plutLeft[COLUMNS*slice + col] = (col - 1 + 9) % 9 + COLUMNS*slice;
                plutRight[COLUMNS*slice + col] = (col + 1) % 9 + COLUMNS*((slice + 1) % SLICES);
            }
        }
    }
	for (int n=0;n<24;n++) {
		for (int i=0;i<243;i++) {
			uint8_t val = round_constants[n][i];
			simd_expandTrit(val, &simd_round_constants[n][i]);
		}
	}
}

void TroikaPermutation(Trit *state, unsigned long long num_rounds)
{
    unsigned long long round;

    assert(num_rounds <= NUM_ROUNDS);

    //PrintTroikaState(state);
    for (round = 0; round < num_rounds; round++) {
//        printState(0, state, 729);
        SubTrytes(state);
//        printState(0, state, 729);
        ShiftRowsAndLanes(state);
//        printState(0, state, 729);
        AddColumnParity(state);
//        printState(0, state, 729);
        AddRoundConstant(state, round);
//        printState(0, state, 729);
    }
    //PrintTroikaState(state);
}

static void TroikaAbsorb(Trit *state, unsigned int rate, const Trit *message,
                         unsigned long long message_length,
                         unsigned long long num_rounds)
{
    unsigned long long trit_idx;

    while (message_length >= rate) {
        // Copy message block over the state
        for (trit_idx = 0; trit_idx < rate; ++trit_idx) {
            state[trit_idx] = message[trit_idx];
        }
        TroikaPermutation(state, num_rounds);
        message_length -= rate;
        message += rate;
    }

    // Pad last block
    Trit last_block[rate];
//    memset(last_block, 0, rate);
    for (unsigned int i=0;i<rate;i++) {
    	simd_set_zero(&last_block[i]);
    	//*pState++ = zero;
    }


    // Copy over last incomplete message block
    for (trit_idx = 0; trit_idx < message_length; ++trit_idx) {
        last_block[trit_idx] = message[trit_idx];
    }

    // Apply padding
//#if SIMD_SIZE!=128
    last_block[trit_idx] = PADDING;
//#else

//#endif

    // Insert last message block
    for (trit_idx = 0; trit_idx < rate; ++trit_idx) {
        state[trit_idx] = last_block[trit_idx];
    }
}

static void TroikaSqueeze(Trit *hash, unsigned long long hash_length,
                          unsigned int rate, Trit *state,
                          unsigned long long num_rounds)
{
    unsigned long long trit_idx;
    while (hash_length >= rate) {
        TroikaPermutation(state, num_rounds);
        // Extract rate output
        for (trit_idx = 0; trit_idx < rate; ++trit_idx) {
            hash[trit_idx] = state[trit_idx];
        }
        hash += rate;
        hash_length -= rate;
    }

    // Check if there is a last incomplete block
    if (hash_length % rate) {
        TroikaPermutation(state, num_rounds);
        for (trit_idx = 0; trit_idx < hash_length; ++trit_idx) {
            hash[trit_idx] = state[trit_idx];
        }
    }
}                    

void Troika(Trit *out, unsigned long long outlen,
            const Trit *in, unsigned long long inlen)
{
    TroikaVarRounds(out, outlen, in, inlen, NUM_ROUNDS);
}

void TroikaVarRounds(Trit *out, unsigned long long outlen,
                     const Trit *in, unsigned long long inlen,
                     unsigned long long num_rounds)
{
    Trit state[STATESIZE] __attribute__ ((aligned (16)));

    memset(state, 0, sizeof(state));
    TroikaAbsorb(state, TROIKA_RATE, in, inlen, num_rounds);
    TroikaSqueeze(out, outlen, TROIKA_RATE, state, num_rounds);
}

const char* testVectorResult="100201212212122220110122122111212210022100201102210102201020101211220110102000220002111001021000201212121010120122110101122021221110022000120010102120222202002101112222111011122001222221101010122202121211111101210020221221021020100022202101112";
const char* testVector="100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";

void importStringToArray(const char* input, Trit* output) {
	memset(output, 0, 729);
	for (int i=0;i<243;i++) {
		simd_expandTrit(*input++ - 48, output++);
	}
}



int main() {
	initConstants();
	Trit input[8019]={0};
	Trit result[729]={0};


	importStringToArray(testVector, input);
	long s = get_microtime();
	for (int i=0;i<50000/SIMD_SIZE;i++) {
//		importStringToArray(testVector, input);
		Troika(result, 243, input, 8019);
//		printState(0, result, 729);
	}
	printf("\n");
	long e = get_microtime();
	printf("%d\n", (int) ((e-s)/1000));

	printState(SIMD_SIZE-1, result, 243);

}
