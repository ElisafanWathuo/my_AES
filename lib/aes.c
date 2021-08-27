#define FIELD_POLY 0x1B
#define sBoxConstant 0x63
#define invSboxConstant 0x05


#include "aes.h"

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static const uint8_t mixColumnMatrix[16] = {0x02, 0x03, 0x01, 0x01,
											0x01, 0x02, 0x03, 0x01,
											0x01, 0x01, 0x02, 0x03,
											0x03, 0x01, 0x01, 0x02};
static const uint8_t invMixColumnMatrix[16] = {0x0e, 0x0b, 0x0d, 0x09,
											   0x09, 0x0e, 0x0b, 0x0d,
											   0x0d, 0x09, 0x0e, 0x0b,
											   0x0b, 0x0d, 0x09, 0x0e};

uint8_t gf_add(uint16_t a, uint16_t b)
{
	return (uint8_t) (a ^ b);
} 

uint8_t gf_multiply(uint8_t a, uint8_t b)
{
    uint8_t i;
    uint8_t acc = 0x00; // Accumulator
    uint8_t msb; // Current MSB of a

    for (i = 0; i < 8; ++i)
    {
        // If LSB of b is 1, add a to accumulator
        if (b & 0x01)
        {
            acc ^= a;
        }

        // Store MSB of a, then shift it off
	msb = a & 0x80;
        a <<= 1;

        // If MSB of a was 1, add field polynomial to a
        if (msb)
        {
            a = gf_add(a, FIELD_POLY);
        }

        // Advance to next bit of b
        b >>= 1;
    }

    return acc;
}

void matrixMultiply(const uint8_t* a, uint8_t* b, uint8_t* outC)
{
	int temp = 0;
	for(int i = 0; i < (Nb * Nb); i++)
	{
		temp = (i % Nb) == 0 ? i : temp;
		int tempb = i - temp;
		for(int j = temp; j < (temp + Nb); j++)
		{
			outC[i] ^= gf_multiply(a[j], b[(Nb * (j - temp)) + (i - temp)]);
		}
	}
}

void byteShift(uint8_t* row, int shifts)
{
	while(shifts > 0)
	{
		uint8_t temp = row[0];
		row[0] = row[1];
		row[1] = row[2];
		row[2] = row[3];
		row[4] = temp;
		shifts--;
	}
}

uint8_t bruteForceMultiplicativeInverse(uint8_t num)
{
	if(num == 0)
	{
		return 0;
	}
	uint8_t i = 1;
	while(gf_multiply(num, i) != 1)
	{
		i++;
	}
	return i;
}

/*
 *Bit rotate function for aesSbox
 * */
uint8_t ROTL8(uint8_t num, unsigned int shift)
{
	return (uint8_t) (num << shift) | (num >> (8 - shift));
}


/*
 * Returns the AES(Rijndael) sbox value for an 8 bit integer
 * */
uint8_t aesSbox(uint8_t val)
{
	if(val == 0)
	{
		return sBoxConstant;
	}
	// Multiplicative inverse of val in gf(2^8)
	uint8_t inverseVal = bruteForceMultiplicativeInverse(val);

	uint8_t xFormed = inverseVal ^ ROTL8(inverseVal, 1) ^ ROTL8(inverseVal, 2) ^ ROTL8(inverseVal, 3) ^ ROTL8(inverseVal, 4);

	return (sBoxConstant ^ xFormed);
}

uint8_t aesInvSbox(uint8_t sBoxNum)
{
	return bruteForceMultiplicativeInverse((ROTL8(sBoxNum, 1) ^ ROTL8(sBoxNum, 3) ^ ROTL8(sBoxNum, 6) ^ invSboxConstant));
}

void keyExpansion(uint8_t* roundKey, uint8_t* inputKey)
{
	int i, j, k;
	uint8_t temp[4];

	// Load the input Key into the round key array...
	for(i = 0; i < Nk; i++)
	{
		roundKey[(i * 4) + 0] = inputKey[(i * 4) + 0];
		roundKey[(i * 4) + 1] = inputKey[(i * 4) + 1];
		roundKey[(i * 4) + 2] = inputKey[(i * 4) + 2];
		roundKey[(i * 4) + 3] = inputKey[(i * 4) + 3];
	}

	// Rest of the round keys are computed using the previous round key...
	for(i = Nk; i < (Nb * (Nr + 1)); i++)
	{
		{
			k = (i - 1) * 4; // Set k to the index of the last word on the Round Key...
			// Copy the last word on roundKey to temp...
			temp[0] = roundKey[k + 0];
			temp[1] = roundKey[k + 1];
			temp[2] = roundKey[k + 2];
			temp[3] = roundKey[k + 3];
		}

		if((i % Nk) == 0)
		{
			/*
			 * Enter the G function if i is a multiple of Nk
			 * The G function rotates the word held by temp array by one byte to the left.
			 * Each byte is then substituted using the AES Sbox.
			 * The first byte is then XOred using the Round Coefficient Array Rcon[i/Nk]
			 * 
			 * */

			// Rotate one Byte to the Left...
			uint8_t tempo = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = tempo;

			// Byte Substitution using Sbox...
			temp[0] = aesSbox(temp[0]);
			temp[1] = aesSbox(temp[1]);
			temp[2] = aesSbox(temp[2]);
			temp[3] = aesSbox(temp[3]);

			// XOR first byte with Rcon[i/Nk]...
			temp[0] ^= Rcon[i / Nk];
		}

		/*
		 *
		 * For AES256 Run the H function when (i % Nk) == 4
		 * The H function performs a straight Sbox Substitution for 
		 * the word held by the temp array..
		 *
		 * */
		if((Nk == 8) && ((i % Nk) == 4))
		{
			temp[0] = aesSbox(temp[0]);
			temp[1] = aesSbox(temp[1]);
			temp[2] = aesSbox(temp[2]);
			temp[3] = aesSbox(temp[3]);
		}
		j = i * 4; k=(i - Nk) * 4;
    	roundKey[j + 0] = roundKey[k + 0] ^ temp[0];
    	roundKey[j + 1] = roundKey[k + 1] ^ temp[1];
    	roundKey[j + 2] = roundKey[k + 2] ^ temp[2];
    	roundKey[j + 3] = roundKey[k + 3] ^ temp[3];
	}
}

void shiftRows(uint8_t* state)
{
	uint8_t temp[4];
	for(int i = 0; i < 4; i++)
	{
		temp[0] = state[(i * 4) + 0];
		temp[1] = state[(i * 4) + 1];
		temp[2] = state[(i * 4) + 2];
		temp[3] = state[(i * 4) + 3];

		// byte shift i times...
		byteShift(temp, i);

		// Make the changes on state...
		state[(i * 4) + 0] = temp[0];
		state[(i * 4) + 1] = temp[1];
		state[(i * 4) + 2] = temp[2];
		state[(i * 4) + 3] = temp[3];
	}
}

void mixColumns(uint8_t* state)
{
	uint8_t temp[16];
	for(int i = 0; i < 16; i++)
			temp[i] = 0;

	matrixMultiply(mixColumnMatrix, state, temp);

	for(int i = 0; i < 4; i++)
	{
		state[(i * 4) + 0] = temp[(i * 4) + 0];
		state[(i * 4) + 1] = temp[(i * 4) + 1];
		state[(i * 4) + 2] = temp[(i * 4) + 2];
		state[(i * 4) + 3] = temp[(i * 4) + 3];
	}
}

void byteSubstitution(uint8_t* state)
{
	for(int i = 0; i < 4; i++)
	{
		state[(i * 4) + 0] = aesSbox(state[(i * 4) + 0]);
		state[(i * 4) + 1] = aesSbox(state[(i * 4) + 1]);
		state[(i * 4) + 2] = aesSbox(state[(i * 4) + 2]);
		state[(i * 4) + 3] = aesSbox(state[(i * 4) + 3]);
	}
}

void invByteSubstitution(uint8_t* state)
{
	for(int i = 0; i < 4; i++)
	{
		state[(i * 4) + 0] = aesInvSbox(state[(i * 4) + 0]);
		state[(i * 4) + 1] = aesInvSbox(state[(i * 4) + 1]);
		state[(i * 4) + 2] = aesInvSbox(state[(i * 4) + 2]);
		state[(i * 4) + 3] = aesInvSbox(state[(i * 4) + 3]);
	}
}

void invShiftRows(uint8_t* state)
{
	uint8_t temp[4];
	for(int i = 0; i < 4; i++)
	{
		if(i)
		{
			temp[0] = state[(i * 4) + 0];
			temp[1] = state[(i * 4) + 1];
			temp[2] = state[(i * 4) + 2];
			temp[3] = state[(i * 4) + 3];

			byteShift(temp, (4 - i));

			state[(i * 4) + 0] = temp[0];
			state[(i * 4) + 1] = temp[1];
			state[(i * 4) + 2] = temp[2];
			state[(i * 4) + 3] = temp[3];
		}
	}
}

void invMixColumns(uint8_t* state)
{
	uint8_t temp[16];
	for(int i = 0; i < 16; i++)
			temp[i] = 0;

	matrixMultiply(invMixColumnMatrix, state, temp);

	for(int i = 0; i < 4; i++)
	{
		state[(i * 4) + 0] = temp[(i * 4) + 0];
		state[(i * 4) + 1] = temp[(i * 4) + 1];
		state[(i * 4) + 2] = temp[(i * 4) + 2];
		state[(i * 4) + 3] = temp[(i * 4) + 3];
	}
}

void addRoundKey(uint8_t round, uint8_t* state,const uint8_t* roundKey)
{
	for(int i = 0; i < 4; i++)
	{
		state[(i * 4) + 0] ^= roundKey[(round * Nb * 4) + ((i * 4) + 0)];
		state[(i * 4) + 1] ^= roundKey[(round * Nb * 4) + ((i * 4) + 1)];
		state[(i * 4) + 2] ^= roundKey[(round * Nb * 4) + ((i * 4) + 2)];
		state[(i * 4) + 3] ^= roundKey[(round * Nb * 4) + ((i * 4) + 3)];
	}
}

void aesInit(struct AES *context, uint8_t* inputKey)
{
	keyExpansion(context->roundKey, inputKey);
}

void aesEncrypt(uint8_t* state, const struct AES *context)
{
	addRoundKey(0, state, context->roundKey);
	uint8_t round = 1;
	while(round < Nr)
	{
		byteSubstitution(state);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(round, state, context->roundKey);
		round++;
	}
	byteSubstitution(state);
	shiftRows(state);
	addRoundKey(Nr, state, context->roundKey);
}

void aesDecrypt(uint8_t* state, const struct AES *context)
{
	addRoundKey(Nr, state, context->roundKey);

	uint8_t round  = Nr - 1;
	while(round >= 1)
	{
		invShiftRows(state);
		invByteSubstitution(state);
		addRoundKey(round, state, context->roundKey);
		invMixColumns(state);
		round--;
	}
	invShiftRows(state);
	invByteSubstitution(state);
	addRoundKey(0, state, context->roundKey);
}
