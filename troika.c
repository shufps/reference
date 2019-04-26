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
#if SIMD_SIZE==64
const Trit PADDING={0xffffffffffffffffll, 0x0000000000000000ll};
#elif SIMD_SIZE==32
const Trit PADDING={0xffffffff, 0x00000000};
#endif

static Trit simd_round_constants[NUM_ROUNDS][COLUMNS*SLICES];

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


uint8_t simd_exportValue(int nr, Trit* t) {
	Trit tmp;
	tmp.lo = ((t->hi) >> nr) & 0x1;
	tmp.hi = ((~(t->lo ^ t->hi)) >> nr) & 0x1;
	uint8_t val = tmp.lo | (tmp.hi << 1);
	return val;
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


Trit* simd_set_zero(Trit* a) {
#if SIMD_SIZE==64
	a->hi = 0x0000000000000000;
	a->lo = 0xffffffffffffffff;
#elif SIMD_SIZE==32
	a->hi = 0x00000000;
	a->lo = 0xffffffff;
#endif
	return a;
}

Trit* simd_add_mod3(Trit* a, Trit* b, Trit* c) {
	Trit tmp;
	tmp.hi = ((a->hi & b->lo)) | (~(a->lo ^ b->hi) & (~a->hi & ~b->lo));
	tmp.lo = ((a->lo & b->lo)) | (~(a->hi ^ a->lo) & (b->hi)) | (~(b->hi ^ b->lo) & (a->hi));
	c->hi = tmp.hi;
	c->lo = tmp.lo;
	return c;
}

void simd_sbox(Trit* a2, Trit* a1, Trit* a0) {
	Trit d2, d1, d0;
	d2.hi = (~(a2->hi ^ a0->lo) & (a1->hi)) | ((a2->hi ^ a1->hi) & (~a1->lo & ~a0->lo)) | ((a2->hi ^ a1->hi ^ a1->lo) & (a0->hi & ~a2->lo)) | (~(a0->hi ^ a0->lo) & (a2->lo & a1->lo));
	d2.lo = (~(a2->hi ^ a1->lo) & (a0->lo)) | ((a2->hi ^ a0->lo) & (a1->lo));
	d1.hi = (~(a2->hi ^ a2->lo) & (a1->lo)) | ((a2->lo ^ a1->lo) & (a0->lo & ~a2->hi)) | ((a2->hi ^ a1->hi ^ a0->hi) & (~a2->lo & ~a1->lo & ~a0->lo));
	d1.lo = ((a2->hi & a0->lo)) | (~(a2->lo ^ a1->hi ^ a0->hi) & (~a2->hi & ~a1->lo & ~a0->lo)) | ((a1->lo ^ a0->lo) & (a2->hi));
	d0.hi = ((a2->hi & a0->hi)) | ((a2->hi ^ a1->lo) & (a0->hi)) | (~(a2->lo ^ a1->hi ^ a0->lo) & (~a2->hi & ~a1->lo & ~a0->hi));
	d0.lo = ((a1->lo & a0->lo)) | ((a2->lo ^ a1->hi ^ a0->hi) & (~a2->hi & ~a1->lo & ~a0->lo)) | ((a2->hi ^ a1->lo) & (a0->lo));
    *a2 = d2;
    *a1 = d1;
    *a0 = d0;
}

void SubTrytes(Trit *state)
{
    int sbox_idx;
    for (sbox_idx = 0; sbox_idx < NUM_SBOXES; ++sbox_idx) {
    	simd_sbox(&state[3*sbox_idx], &state[3*sbox_idx+1], &state[3*sbox_idx+2]);
    }
}

void ShiftRows(Trit *state)
{
    int slice, row, col, old_idx, new_idx;

    Trit new_state[STATESIZE];

    for (slice = 0; slice < SLICES; ++slice) {
        for (row = 0; row < ROWS; ++row) {
            for (col = 0; col < COLUMNS; ++col) {
                old_idx = SLICESIZE*slice + COLUMNS*row + col;
                new_idx = SLICESIZE*slice + COLUMNS*row + 
                          (col + 3*shift_rows_param[row]) % COLUMNS;
                new_state[new_idx] = state[old_idx];
            }
        }
    }

    memcpy(state, new_state, sizeof(new_state));
}

void ShiftLanes(Trit *state)
{
    int slice, row, col, old_idx, new_idx, new_slice;

    Trit new_state[STATESIZE];

    for (slice = 0; slice < SLICES; ++slice) {
        for (row = 0; row < ROWS; ++row) {
            for (col = 0; col < COLUMNS; ++col) {
                old_idx = SLICESIZE*slice + COLUMNS*row + col;
                new_slice = (slice + shift_lanes_param[col + COLUMNS*row]) % SLICES;
                new_idx = SLICESIZE*(new_slice) + COLUMNS*row + col;
                new_state[new_idx] = state[old_idx];
            }
        }
    }

    memcpy(state, new_state, sizeof(new_state));
}

void AddColumnParity(Trit *state)
{
    int slice, row, col, idx;

    Trit parity[SLICES * COLUMNS];

    // First compute parity for each column
    for (slice = 0; slice < SLICES; ++slice) {
        for (col = 0; col < COLUMNS; ++col) {
        	Trit col_sum_mod3;
        	simd_set_zero(&col_sum_mod3);
        	col_sum_mod3 = state[SLICESIZE*slice + col];
			simd_add_mod3(&state[SLICESIZE*slice + COLUMNS*1 + col], &col_sum_mod3, &col_sum_mod3);
			simd_add_mod3(&state[SLICESIZE*slice + COLUMNS*2 + col], &col_sum_mod3, &col_sum_mod3);
            parity[COLUMNS*slice + col] = col_sum_mod3;
        }
    }

    // Add parity 
    for (slice = 0; slice < SLICES; ++slice) {
        for (row = 0; row < ROWS; ++row) {
            for (col = 0; col < COLUMNS; ++col) {
                idx = SLICESIZE*slice + COLUMNS*row + col;
    			simd_add_mod3(&state[idx], &parity[(col - 1 + 9) % 9 + COLUMNS*slice], &state[idx]);
    			simd_add_mod3(&state[idx], &parity[(col + 1) % 9 + COLUMNS*((slice + 1) % SLICES)], &state[idx]);
            }
        }
    }
}

void AddRoundConstant(Trit *state, int round)
{
    int slice, col, idx;
    //d();
    for (slice = 0; slice < SLICES; ++slice) {
        for (col = 0; col < COLUMNS; ++col) {
            idx = SLICESIZE*slice + col;
			simd_add_mod3(&state[idx], &simd_round_constants[round][slice*COLUMNS + col], &state[idx]);
//			printf("%d %d %d %016lx %016lx\n", slice*COLUMNS + col, idx, round_constants[round][slice*COLUMNS + col],simd_round_constants[round][slice*COLUMNS + col].lo, simd_round_constants[round][slice*COLUMNS + col].hi);
        }
    }    
}

Trit* simd_expandTrit(uint8_t t, Trit* dst) {
	Trit tmp={0};
	if (t & 0x1) {
#if SIMD_SIZE==64
		tmp.lo = 0xffffffffffffffff;
#elif SIMD_SIZE==32
		tmp.lo = 0xffffffff;
#endif
	}
	if (t & 0x2) {
#if SIMD_SIZE==64
		tmp.hi = 0xffffffffffffffff;
#elif SIMD_SIZE==32
		tmp.hi = 0xffffffff;
#endif
	}
	dst->lo = ~(tmp.lo ^ tmp.hi);
	dst->hi = tmp.lo;
	return dst;
}

void CalcRoundConstants() {
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
        SubTrytes(state);
        ShiftRows(state);
        ShiftLanes(state);
        AddColumnParity(state);
        AddRoundConstant(state, round);
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
    for (int i=0;i<rate;i++) {
    	simd_set_zero(&last_block[i]);
    	//*pState++ = zero;
    }


    // Copy over last incomplete message block
    for (trit_idx = 0; trit_idx < message_length; ++trit_idx) {
        last_block[trit_idx] = message[trit_idx];
    }

    // Apply padding
    last_block[trit_idx] = PADDING;

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

#if SIMD_SIZE==64
/*    __int128_t zero = 0xffffffffffffffff0000000000000000ll;
    __int128_t* pState = (__int128_t*) state;*/
    for (int i=0;i<729;i++) {
    	simd_set_zero(&state[i]);
    	//*pState++ = zero;
    }
#elif SIMD_SIZE==32
    uint64_t zero = 0x00000000ffffffff;
    uint64_t* pState = (uint64_t*) state;
    for (int i=0;i<729;i++) {
    	*pState++ = zero;
    }
#endif

//    memset(state, 0, sizeof(state));
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
	CalcRoundConstants();
	Trit input[8019]={0};
	Trit result[729]={0};

	importStringToArray(testVector, input);
	long s = get_microtime();
	for (int i=0;i<50000/64;i++) {
//		importStringToArray(testVector, input);
		Troika(result, 243, input, 8019);
//		printState(0, result, 729);
	}
	printf("\n");
	long e = get_microtime();
	printf("%d\n", (int) ((e-s)/1000));

	printState(0, result, 243);

}
