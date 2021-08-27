#include <stdint.h>

#ifndef _AES_H_
#define _AES_H_

#define AES256 1

#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
	#define aesRoundKeySize 240
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
	#define aesRoundKeySize 208
#else
    #define Nk 4
    #define Nr 10
	#define aesRoundKeySize 176
#endif


struct AES
{
	uint8_t roundKey[aesRoundKeySize];
};

uint8_t gf_add(uint16_t a, uint16_t b);
uint8_t gf_multiply(uint8_t a, uint8_t b);
void matrixMultiply(const uint8_t* a, uint8_t* b, uint8_t* outC);
void byteShift(uint8_t* row, int shifts);
uint8_t bruteForceMultiplicativeInverse(uint8_t num);
uint8_t ROTL8(uint8_t num, unsigned int shift);
uint8_t aesSbox(uint8_t val);
uint8_t aesInvSbox(uint8_t sBoxNum);
void keyExpansion(uint8_t* roundKey, uint8_t* inputKey);
void shiftRows(uint8_t* state);
void mixColumns(uint8_t* state);
void byteSubstitution(uint8_t* state);
void invByteSubstitution(uint8_t* state);
void invShiftRows(uint8_t* state);
void invMixColumns(uint8_t* state);
void addRoundKey(uint8_t round, uint8_t* state, const uint8_t* roundKey);
void aesInit(struct AES *context, uint8_t* inputKey);
void aesEncrypt(uint8_t* state, const struct AES *context);
void aesDecrypt(uint8_t* state, const struct AES *context);

#endif  //_AES_H
