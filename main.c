#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "troika.h"
#include "stroika.h"

const char* testVectorResult="100201212212122220110122122111212210022100201102210102201020101211220110102000220002111001021000201212121010120122110101122021221110022000120010102120222202002101112222111011122001222221101010122202121211111101210020221221021020100022202101112";
const char* testVector="100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";
const char* ref_vector="120220121212020211012202221121212221211022112222201212001221011202211020020000200100012021222011211111202210102202211120102211222000002210202121001221010022001101021010000021221011220002100012221020010112001222020112100211020221121101101102212";

void insertMessage(int nr, uint8_t* input, SIMD_Trit* trits, int len);
void simd_exportState(int nr, SIMD_Trit* state, uint8_t* trits, int len);

void importStringToSIMD(int nr, uint8_t* input, SIMD_Trit* output) {
/*	memset(output, 0, 243);
	for (int i=0;i<243;i++) {
		simd_expandTrit(*input++ - 48, output++);
	}*/

	char data[243];
	for (int i=0;i<243;i++) {
		data[i] = input[i]-48;
	}
	insertMessage(nr, (uint8_t*) data, output, 243);
}

void bigRandomTest(int loops) {
	SIMD_Trit simdInput[8019];
	SIMD_Trit simdOutput[1024];

	uint8_t input[8019];
	uint8_t output[1024];
	uint8_t output_ref[1024];

	uint8_t retval = 1;

	for (int k=0;k<loops;k++) {
		for (int i=0;i<8019;i++) {
			input[i] = rand() % 2;
		}

		uint64_t message_length = rand() % 8019;
		uint64_t hash_length = rand() % 1024;
//		printf("message_length: %d\n", message_length);
//		printf("hash_length: %d\n", hash_length);
		// calculate reference output
		Troika(output_ref, hash_length, input, message_length);


		insertMessage(SIMD_SIZE-1, input, simdInput, message_length);

		TROIKA_CTX ctx;
		memset(&ctx, 0, sizeof(ctx));
		uint32_t ofs = 0;
		uint32_t rest = message_length;
		while (1) {
			uint32_t chunk = (rand() % rest)+1;
			if (!chunk)
				continue;
//			printf("absorbing chunk with %d Trits\n", chunk);
			STroikaAbsorb(&ctx, TROIKA_RATE, &simdInput[ofs], chunk, 24);
			if (chunk == rest) {
				break;
			}
			ofs += chunk;
			rest -= chunk;
		}
		STroikaSqueeze(simdOutput, hash_length, TROIKA_RATE, &ctx, 24);
		simd_exportState(SIMD_SIZE-1, simdOutput, output, hash_length);

		for (uint32_t i=0;i<hash_length;i++) {
			if (output[i] != output_ref[i]) {
				printf("error %d\n", i);
				retval = 0;
			}
		}
		if (!retval)
			break;
	}
	printf("Big Random Test: %s\n",retval?"PASS":"FAIL");
}

/*
// splits a block into 2 chunks and absorbs then one after another
void testSmallAbsorbs() {
	int retval = 1;
	SIMD_Trit simdResult[729]={0};
	SIMD_Trit tv[8019]={0};

	uint8_t result[729];

	importStringToSIMD(SIMD_SIZE-1, testVector, tv);
	printState(SIMD_SIZE-1, tv, 243);

	for (int j=0;j<243;j++) {
		TROIKA_CTX ctx;
		memset(&ctx, 0, sizeof(ctx));
		STroikaAbsorb(&ctx, 243, &tv[0], j, 24);
		STroikaAbsorb(&ctx, 243, &tv[j], 243-j, 24);
		STroikaSqueeze(simdResult, 243, 243, &ctx, 24);

		simd_exportState(SIMD_SIZE-1, simdResult, result);

		for (int i=0;i<243;i++) {
			if ((ref_vector[i] - 48) != result[i])
				retval = 0;
		}
	}
	printf("small Absorbs: %s\n",retval?"PASS":"FAIL");
}
*/
int main() {
	STroikaInit();
	bigRandomTest(10000);
#if 0

	testSmallAbsorbs();

	SIMD_Trit input[8019]={0};
	SIMD_Trit result[729]={0};


	importStringToSIMD(SIMD_SIZE-1, testVector, input);
	printState(SIMD_SIZE-1, input, 243);
	long s = get_microtime();
	for (int i=0;i<1/*10/SIMD_SIZE*/;i++) {
//		importStringToArray(testVector, input);
		STroika(result, 243, input, 243);
//		printState(0, result, 729);
	}
	printf("\n");
	long e = get_microtime();
	printf("%d\n", (int) ((e-s)/1000));

	printState(SIMD_SIZE-1, result, 243);
#endif
}
