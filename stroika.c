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

#include "stroika.h"

#include <sys/time.h>

static SIMD_Trit simd_round_constants[NUM_ROUNDS][COLUMNS*SLICES];
static SIMD_Trit PADDING;

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

/*void PrintTroikaSlice(uint8_t *state, int slice)
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
*/
#ifdef DEBUG
#define inline
#endif

inline uint8_t simd_exportValue(int nr, SIMD_Trit* t) {
#if SIMD_SIZE!=128 && SIMD_SIZE != 256
	return ((t->lo >> nr) & 0x1) | ((((t->lo ^ t->hi) >> nr) & 0x1) << 1);
#elif SIMD_SIZE == 128 // TODO: this probably is wrong
	uint64_t tmpLo[2];
	uint64_t tmpHi[2];
	_mm_store_si128((__m128i*) tmpLo, t->lo);
	_mm_store_si128((__m128i*) tmpHi, t->hi ^ t->lo);
	uint8_t bitLo = (uint8_t) ((tmpLo[nr / 64] >> (nr % 64)) & 0x1);
	uint8_t bitHi = (uint8_t) ((tmpHi[nr / 64] >> (nr % 64)) & 0x1);
	return bitLo | (bitHi << 1);
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

void simd_exportState(int nr, SIMD_Trit* state, uint8_t* trits, int len) {
	for (int i=0;i<len;i++) {
		*trits++ = simd_exportValue(nr, state++);
	}
}

void printState(int nr, SIMD_Trit* state, int len) {
	uint8_t trits[729];
	simd_exportState(nr, state, trits, 729);
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

static inline void simd_expandTrit(uint8_t t, SIMD_Trit* dst) {
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


// insert message into SIMD-registers at specific position
// uses uint32 for access to data
void insertMessage(int nr, uint8_t* input, SIMD_Trit* trits, int len) {
	for (int i=0;i<len;i++) {
		uint32_t* pLo = (uint32_t*) &trits[i].lo;
		uint32_t* pHi = (uint32_t*) &trits[i].hi;
		uint32_t ofs = nr / 32;
		uint32_t bit = 1 << (nr % 32);

		char lo = input[i] & 0x1;
		char hi = !!(input[i] & 0x2) ^ lo;

		if (lo)
			pLo[ofs] |= bit;
		else
			pLo[ofs] &= ~bit;

		if (hi)
			pHi[ofs] |= bit;
		else
			pHi[ofs] &= ~bit;
	}
}



static inline void simd_set_zero(SIMD_Trit* a) {
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

static inline SIMD_Trit* simd_add_mod3(SIMD_Trit* a, SIMD_Trit* b, SIMD_Trit* c) {
	SIMD_Trit tmp;
	tmp.hi = ((a->hi ^ b->hi)) | ((a->hi ^ a->lo ^ b->lo));
	tmp.lo = ((b->lo & ~a->hi)) | ((a->lo ^ b->hi) & (a->hi & ~b->lo));
	c->hi = tmp.hi;
	c->lo = tmp.lo;
	return c;
}

static inline void simd_sbox(SIMD_Trit* a, SIMD_Trit* b, SIMD_Trit* c) {
	SIMD_Trit d2, d1, d0;
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


void SSubTrytes(TROIKA_CTX* ctx)
{
    for (int i=0;i<729;i+=9) {
    	simd_sbox(&ctx->state[i], &ctx->state[i+1], &ctx->state[i+2]);
    	simd_sbox(&ctx->state[i+3], &ctx->state[i+4], &ctx->state[i+5]);
    	simd_sbox(&ctx->state[i+6], &ctx->state[i+7], &ctx->state[i+8]);
    }
}

void SShiftRowsAndLanes(TROIKA_CTX* ctx)
{
    SIMD_Trit newstate[729];
    for (int i=0;i<729;i++) {
		newstate[i] = ctx->state[perm[i]];
    }
    memcpy(ctx->state, newstate, sizeof(newstate));
}



void SAddColumnParity(TROIKA_CTX* ctx)
{
    int slice,  col;

    SIMD_Trit parity[SLICES * COLUMNS];

    int pIdx = 0;
    int sIdx = 0;
    for (slice = 0;slice<SLICES;slice++) {
    	for (col=0;col<COLUMNS;col++, pIdx++, sIdx++) {
    		SIMD_Trit col_sum_mod3;
    		col_sum_mod3 = ctx->state[sIdx];
    		simd_add_mod3(&ctx->state[sIdx + 9], &col_sum_mod3, &col_sum_mod3);
    		simd_add_mod3(&ctx->state[sIdx + 18], &col_sum_mod3, &col_sum_mod3);
    		parity[pIdx] = col_sum_mod3;
    	}
    	sIdx += 18;
    }

    pIdx = 0;
    sIdx = 0;
    // Add parity
    for (slice = 0; slice < SLICES; ++slice) {
		for (col = 0; col < COLUMNS; ++col, sIdx++, pIdx++) {
			simd_add_mod3(&ctx->state[sIdx], &parity[plutLeft[pIdx]], &ctx->state[sIdx]);
			simd_add_mod3(&ctx->state[sIdx], &parity[plutRight[pIdx]], &ctx->state[sIdx]);
			simd_add_mod3(&ctx->state[sIdx+9], &parity[plutLeft[pIdx]], &ctx->state[sIdx+9]);
			simd_add_mod3(&ctx->state[sIdx+9], &parity[plutRight[pIdx]], &ctx->state[sIdx+9]);
			simd_add_mod3(&ctx->state[sIdx+18], &parity[plutLeft[pIdx]], &ctx->state[sIdx+18]);
			simd_add_mod3(&ctx->state[sIdx+18], &parity[plutRight[pIdx]], &ctx->state[sIdx+18]);
		}
		sIdx+=18;
    }
}

void SAddRoundConstant(TROIKA_CTX* ctx, int round)
{
    int slice, col, idx;
    for (slice = 0; slice < SLICES; ++slice) {
        for (col = 0; col < COLUMNS; ++col) {
            idx = SLICESIZE*slice + col;
			simd_add_mod3(&ctx->state[idx], &simd_round_constants[round][slice*COLUMNS + col], &ctx->state[idx]);
        }
    }
}


void STroikaInit() {
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

	simd_expandTrit(1, &PADDING);
}

void STroikaPermutation(TROIKA_CTX* ctx, unsigned long long num_rounds)
{
    unsigned long long round;

    assert(num_rounds <= NUM_ROUNDS);

    //PrintTroikaState(state);
    for (round = 0; round < num_rounds; round++) {
//        printState(0, state->state, 729);
        SSubTrytes(ctx);
//        printState(0, state->state, 729);
        SShiftRowsAndLanes(ctx);
//        printState(0, state->state, 729);
        SAddColumnParity(ctx);
//        printState(0, state->state, 729);
        SAddRoundConstant(ctx, round);
//        printState(0, state->state, 729);
    }
    //PrintTroikaState(state);
}

void STroikaAbsorb(TROIKA_CTX* ctx, unsigned int rate, const SIMD_Trit *message,
                         uint64_t message_length,
                         unsigned long long num_rounds)
{
    unsigned idx = ctx->rest;
	ctx->rest = (ctx->rest + message_length) % TROIKA_RATE;

	if (idx) {
		uint64_t left = TROIKA_RATE - idx;
		// TODO can it be copied to state directly?
		memcpy(ctx->message + idx, message, (message_length < left ? message_length : left) * sizeof(SIMD_Trit));

		if (message_length < left)
			return;

		memcpy(ctx->state, ctx->message, TROIKA_RATE * sizeof(SIMD_Trit));
		STroikaPermutation(ctx, num_rounds);
		message += left;
		message_length -= left;
	}


    while (message_length >= rate) {
		memcpy(ctx->state, message, TROIKA_RATE * sizeof(SIMD_Trit));
        STroikaPermutation(ctx, num_rounds);
        message_length -= rate;
        message += rate;
    }
	if (message_length) {
		memcpy(ctx->message, message, message_length * sizeof(SIMD_Trit));
	}
}

void STroikaSqueeze(SIMD_Trit* hash, unsigned long long hash_length,
                          unsigned int rate, TROIKA_CTX* ctx,
                          unsigned long long num_rounds)
{
	// Copy over last incomplete message block
	memcpy(ctx->state, ctx->message, ctx->rest * sizeof(SIMD_Trit));
	memset(&ctx->state[ctx->rest], 0, (TROIKA_RATE - ctx->rest) * sizeof(SIMD_Trit));
	ctx->state[ctx->rest] = PADDING;

    while (hash_length >= rate) {
        STroikaPermutation(ctx, num_rounds);
        // Extract rate output
        memcpy(hash, ctx->state, TROIKA_RATE * sizeof(SIMD_Trit));
        hash += rate;
        hash_length -= rate;
    }

    // Check if there is a last incomplete block
    if (hash_length > 0) {
        STroikaPermutation(ctx, num_rounds);
        memcpy(hash, ctx->state, hash_length * sizeof(SIMD_Trit));
    }
}                    

void STroika(SIMD_Trit *out, unsigned long long outlen,
            const SIMD_Trit *in, unsigned long long inlen)
{
    STroikaVarRounds(out, outlen, in, inlen, NUM_ROUNDS);
}

void STroikaVarRounds(SIMD_Trit *out, unsigned long long outlen,
                     const SIMD_Trit *in, unsigned long long inlen,
                     unsigned long long num_rounds)
{
	TROIKA_CTX state __attribute__ ((aligned (16)));	// alignment important

    memset(&state, 0, sizeof(TROIKA_CTX));
    STroikaAbsorb(&state, TROIKA_RATE, in, inlen, num_rounds);
    STroikaSqueeze(out, outlen, TROIKA_RATE, &state, num_rounds);
}


