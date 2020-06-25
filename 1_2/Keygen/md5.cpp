#include "md5.h"

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

   /* MD5 initialization. Begins an MD5 operation, writing a new context.
	*/
void MD5Init(MD5Context* context)                                     
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
  */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
void MD5Update(MD5Context* context, unsigned char* input, unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((UINT4)inputLen << 3))

		< ((UINT4)inputLen << 3))
		context->count[1]++;
	context->count[1] += ((UINT4)inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
  */
	if (inputLen >= partLen) {
		MD5_memcpy
		((unsigned char*)&context->buffer[index], (unsigned char*)input, partLen);
		MD5Transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			MD5Transform(context->state, &input[i]);

		index = 0;
	}
	else
		i = 0;

	/* Buffer remaining input */
	MD5_memcpy
	((unsigned char*)&context->buffer[index], (unsigned char*)&input[i],
		inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final(unsigned char* digest, MD5Context* context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.
  */
	index = (unsigned int)((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	MD5Update(context, PADDING, padLen);

	/* Append length (before padding) */
	MD5Update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information.
  */
	MD5_memset((unsigned char*)context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5Transform(UINT4 state[], unsigned char block[])
{
	UINT4 a = state[0], b = state[1], c = state[2], d = state[3], xx[16], State0, State1, State2, State3;
	State0 = state[0];
	State1 = state[1];
	State2 = state[2];
	State3 = state[3];

	Decode(xx, block, 64);

	__asm
	{
		PUSHAD
		MOV EBX, 0x98BADCFE
		MOV EDI, 0xEFCDAB89
		MOV EAX, EDI
		MOV ECX, EBX
		NOT EAX
		AND EAX, d
		AND ECX, EDI
		OR EAX, ECX
		MOV ECX, a
		ADD EAX, DWORD PTR DS : xx[0]
		ADD ECX, EAX
		MOV EAX, ECX
		SHR EAX, 0x1D
		SHL ECX, 3
		OR EAX, ECX
		MOV ECX, EDI
		MOV EDX, EAX
		AND ECX, EAX
		NOT EDX
		AND EDX, EBX
		MOV a, EAX
		OR EDX, ECX
		MOV ECX, d
		ADD EDX, DWORD PTR DS : xx[4]
		ADD ECX, EDX
		MOV EAX, ECX
		SHR EAX, 0x19
		SHL ECX, 7
		OR EAX, ECX
		MOV ECX, EAX
		MOV EDX, EAX
		AND EDX, a
		NOT ECX
		AND ECX, EDI
		OR ECX, EDX
		ADD ECX, DWORD PTR DS : xx[8]
		ADD EBX, ECX
		MOV ECX, EBX
		SHR ECX, 0x15
		SHL EBX, 0x0B
		OR ECX, EBX
		MOV EBX, EAX
		MOV EDX, ECX
		AND EBX, ECX
		NOT EDX
		AND EDX, a
		OR EDX, EBX
		MOV EBX, ECX
		ADD EDX, DWORD PTR DS : xx[12]
		ADD EDI, EDX
		MOV EDX, EDI
		SHL EDX, 0x13
		SHR EDI, 0x0D
		OR EDX, EDI
		MOV EDI, EDX
		AND EBX, EDX
		NOT EDI
		AND EDI, EAX
		MOV b, EDX
		OR EDI, EBX
		MOV EBX, a
		ADD EDI, DWORD PTR DS : xx[16]
		ADD EBX, EDI
		MOV EDI, EBX
		SHR EDI, 0x1D
		SHL EBX, 3
		OR EDI, EBX
		MOV a, EDI
		MOV EBX, EDI
		AND EDX, EDI
		NOT EBX
		AND EBX, ECX
		MOV EDI, b
		OR EBX, EDX
		ADD EBX, DWORD PTR DS : xx[20]
		ADD EAX, EBX
		MOV EDX, EAX
		SHR EDX, 0x19
		SHL EAX, 7
		OR EDX, EAX
		MOV EAX, EDX
		MOV EBX, EDX
		AND EBX, a
		NOT EAX
		AND EAX, EDI
		OR EAX, EBX
		MOV EBX, EDX
		ADD EAX, DWORD PTR DS : xx[24]
		ADD ECX, EAX
		MOV EAX, ECX
		SHR EAX, 0x15
		SHL ECX, 0x0B
		OR EAX, ECX
		MOV ECX, EAX
		AND EBX, EAX
		NOT ECX
		AND ECX, a
		OR ECX, EBX
		MOV EBX, EAX
		ADD ECX, DWORD PTR DS : xx[28]
		ADD EDI, ECX
		MOV ECX, EDI
		SHL ECX, 0x13
		SHR EDI, 0x0D
		OR ECX, EDI
		MOV EDI, ECX
		AND EBX, ECX
		NOT EDI
		AND EDI, EDX
		MOV b, ECX
		OR EDI, EBX
		MOV EBX, a
		ADD EDI, DWORD PTR DS : xx[32]
		ADD EBX, EDI
		MOV EDI, EBX
		SHR EDI, 0x1D
		SHL EBX, 3
		OR EDI, EBX
		MOV EBX, EDI
		AND ECX, EDI
		NOT EBX
		AND EBX, EAX
		MOV a, EDI
		OR EBX, ECX
		MOV EDI, b
		ADD EBX, DWORD PTR DS : xx[36]
		ADD EDX, EBX
		MOV ECX, EDX
		SHR ECX, 0x19
		SHL EDX, 7
		OR ECX, EDX
		MOV EDX, ECX
		MOV EBX, ECX
		AND EBX, a
		NOT EDX
		AND EDX, EDI
		OR EDX, EBX
		MOV EBX, ECX
		ADD EDX, DWORD PTR DS : xx[40]
		ADD EAX, EDX
		MOV EDX, EAX
		SHR EDX, 0x15
		SHL EAX, 0x0B
		OR EDX, EAX
		MOV EAX, EDX
		AND EBX, EDX
		NOT EAX
		AND EAX, a
		OR EAX, EBX
		ADD EAX, DWORD PTR DS : xx[44]
		MOV EBX, EDX
		ADD EDI, EAX
		MOV EAX, EDI
		SHL EAX, 0x13
		SHR EDI, 0x0D
		OR EAX, EDI
		MOV EDI, EAX
		AND EBX, EAX
		NOT EDI
		AND EDI, ECX
		MOV b, EAX
		OR EDI, EBX
		MOV EBX, a
		ADD EDI, DWORD PTR DS : xx[48]
		ADD EBX, EDI
		MOV EDI, EBX
		SHR EDI, 0x1D
		SHL EBX, 3
		OR EDI, EBX
		MOV EBX, EDI
		AND EAX, EDI
		NOT EBX
		AND EBX, EDX
		OR EBX, EAX
		ADD EBX, DWORD PTR DS : xx[52]
		ADD ECX, EBX
		MOV EBX, ECX
		SHR EBX, 0x19
		SHL ECX, 7
		OR EBX, ECX
		MOV EAX, EBX
		MOV ECX, EBX
		NOT EAX
		AND EAX, b
		AND ECX, EDI
		OR EAX, ECX
		ADD EAX, DWORD PTR DS : xx[56]
		ADD EDX, EAX
		MOV EAX, EDX
		SHR EAX, 0x15
		SHL EDX, 0x0B
		OR EAX, EDX
		MOV EDX, EBX
		MOV ECX, EAX
		AND EDX, EAX
		NOT ECX
		AND ECX, EDI
		OR ECX, EDX
		MOV EDX, b
		ADD ECX, DWORD PTR DS : xx[60]
		ADD EDX, ECX
		MOV ECX, EDX
		SHL ECX, 0x13
		SHR EDX, 0x0D
		OR ECX, EDX
		MOV EDX, EAX
		MOV b, ECX

		OR EDX, ECX
		MOV ECX, EAX
		AND EDX, EBX
		AND ECX, b
		OR EDX, ECX
		ADD EDX, DWORD PTR DS : xx[0]
		LEA EDI, DWORD PTR DS : [EDI + EDX + 0x5A826999]
		MOV ECX, EDI
		MOV EDX, EDI
		MOV EDI, b
		SHR ECX, 0x1D
		SHL EDX, 3
		OR ECX, EDX
		MOV c, EDI
		OR c, ECX
		AND EDI, ECX
		MOV EDX, c
		AND EDX, EAX
		OR EDX, EDI
		ADD EDX, DWORD PTR DS : xx[16]
		LEA EDX, DWORD PTR DS : [EBX + EDX + 0x5A826999]
		MOV EBX, EDX
		SHR EBX, 0x1B
		SHL EDX, 5
		OR EBX, EDX
		MOV EDX, c
		AND EDX, EBX
		MOV d, EBX
		OR EDX, EDI
		ADD EDX, DWORD PTR DS : xx[32]
		LEA EDX, DWORD PTR DS : [EAX + EDX + 0x5A826999]
		MOV EAX, EDX
		SHR EAX, 0x17
		SHL EDX, 9
		OR EAX, EDX
		MOV EDX, EAX
		MOV EDI, EAX
		OR EDX, ECX
		AND EDI, ECX
		AND EDX, EBX
		OR EDX, EDI
		MOV EDI, b
		ADD EDX, DWORD PTR DS : xx[48]
		LEA EDI, DWORD PTR DS : [EDI + EDX + 0x5A826999]
		MOV EDX, EDI
		SHR EDX, 0x13
		SHL EDI, 0x0D
		OR EDX, EDI
		MOV EDI, EAX
		OR EDI, EDX
		MOV b, EDX
		AND EDI, EBX
		MOV EBX, EAX
		AND EBX, EDX
		OR EDI, EBX
		MOV EBX, d
		ADD EDI, DWORD PTR DS : xx[4]
		LEA ECX, DWORD PTR DS : [ECX + EDI + 0x5A826999]
		MOV EDI, ECX
		SHR EDI, 0x1D
		SHL ECX, 3
		OR EDI, ECX
		MOV ECX, EDX
		AND b, EDI
		OR ECX, EDI
		MOV a, EDI
		MOV EDI, ECX
		AND EDI, EAX
		OR EDI, b
		ADD EDI, DWORD PTR DS : xx[20]
		LEA EBX, DWORD PTR DS : [EBX + EDI + 0x5A826999]
		MOV EDI, EBX
		SHR EDI, 0x1B
		SHL EBX, 5
		OR EDI, EBX
		AND ECX, EDI
		OR ECX, b
		ADD ECX, DWORD PTR DS : xx[36]
		LEA ECX, DWORD PTR DS : [EAX + ECX + 0x5A826999]
		MOV EAX, ECX
		SHR EAX, 0x17
		SHL ECX, 9
		OR EAX, ECX
		MOV ECX, EAX
		MOV EBX, EAX
		OR ECX, a
		AND EBX, a
		AND ECX, EDI
		OR ECX, EBX
		MOV EBX, EAX
		ADD ECX, DWORD PTR DS : xx[52]
		LEA EDX, DWORD PTR DS : [EDX + ECX + 0x5A826999]
		MOV ECX, EDX
		SHR ECX, 0x13
		SHL EDX, 0x0D
		OR ECX, EDX
		MOV EDX, EAX
		OR EDX, ECX
		AND EBX, ECX
		AND EDX, EDI
		OR EDX, EBX
		MOV EBX, a
		ADD EDX, DWORD PTR DS : xx[8]
		LEA EBX, DWORD PTR DS : [EBX + EDX + 0x5A826999]
		MOV EDX, EBX
		MOV c, ECX
		SHR EDX, 0x1D
		SHL EBX, 3
		OR EDX, EBX
		MOV b, ECX
		OR c, EDX
		AND b, EDX
		MOV a, EDX
		MOV EDX, c
		AND EDX, EAX
		OR EDX, b
		ADD EDX, DWORD PTR DS : xx[24]
		LEA EDI, DWORD PTR DS : [EDI + EDX + 0x5A826999]
		MOV EDX, c
		MOV EBX, EDI
		SHR EBX, 0x1B
		SHL EDI, 5
		OR EBX, EDI
		AND EDX, EBX
		MOV d, EBX
		OR EDX, b
		ADD EDX, DWORD PTR DS : xx[40]
		LEA EDX, DWORD PTR DS : [EAX + EDX + 0x5A826999]
		MOV EAX, EDX
		SHR EAX, 0x17
		SHL EDX, 9
		OR EAX, EDX
		MOV EDX, EAX
		MOV EDI, EAX
		OR EDX, a
		AND EDI, a
		AND EDX, EBX
		OR EDX, EDI
		MOV EDI, EAX
		ADD EDX, DWORD PTR DS : xx[56]
		LEA ECX, DWORD PTR DS : [ECX + EDX + 0x5A826999]
		MOV EDX, ECX
		SHR EDX, 0x13
		SHL ECX, 0x0D
		OR EDX, ECX
		MOV ECX, EAX
		OR ECX, EDX
		AND EDI, EDX
		AND ECX, EBX
		MOV c, EDX
		OR ECX, EDI
		MOV EDI, a
		ADD ECX, DWORD PTR DS : xx[12]
		MOV b, EDX
		LEA EDI, DWORD PTR DS : [EDI + ECX + 0x5A826999]
		MOV ECX, EDI
		SHR ECX, 0x1D
		SHL EDI, 3
		OR ECX, EDI
		OR c, ECX
		AND b, ECX
		MOV EDI, c
		AND EDI, EAX
		OR EDI, b
		ADD EDI, DWORD PTR DS : xx[28]
		LEA EDI, DWORD PTR DS : [EBX + EDI + 0x5A826999]
		MOV EBX, EDI
		SHR EBX, 0x1B
		SHL EDI, 5
		OR EBX, EDI
		MOV EDI, c
		AND EDI, EBX
		MOV d, EBX
		OR EDI, b
		ADD EDI, DWORD PTR DS : xx[44]
		LEA EAX, DWORD PTR DS : [EAX + EDI + 0x5A826999]
		MOV EDI, EAX
		SHR EDI, 0x17
		SHL EAX, 9
		OR EDI, EAX
		MOV EAX, EDI
		OR EAX, ECX
		AND EAX, EBX
		MOV EBX, EDI
		AND EBX, ECX
		OR EAX, EBX
		MOV EBX, d
		ADD EAX, DWORD PTR DS : xx[60]
		LEA EDX, DWORD PTR DS : [EDX + EAX + 0x5A826999]
		MOV EAX, EDX
		SHR EAX, 0x13
		SHL EDX, 0x0D
		OR EAX, EDX
		MOV EDX, EBX
		XOR EDX, EDI
		XOR EDX, EAX
		ADD EDX, DWORD PTR DS : xx[0]

		LEA ECX, DWORD PTR DS : [ECX + EDX + 0x6ED9FBA1]
		MOV EDX, ECX
		SHR EDX, 0x1D
		SHL ECX, 3
		OR EDX, ECX
		MOV ECX, EDI
		XOR ECX, EAX
		XOR ECX, EDX
		ADD ECX, DWORD PTR DS : xx[32]
		LEA ECX, DWORD PTR DS : [EBX + ECX + 0x6ED9FBA1]
		MOV EBX, ECX
		SHR EBX, 0x17
		SHL ECX, 9
		OR EBX, ECX
		MOV ECX, EBX
		MOV a, EBX
		XOR ECX, EAX
		XOR ECX, EDX
		ADD ECX, DWORD PTR DS : xx[16]
		LEA ECX, DWORD PTR DS : [EDI + ECX + 0x6ED9FBA1]
		MOV EDI, ECX
		SHR EDI, 0x15
		SHL ECX, 0x0B
		OR EDI, ECX
		XOR a, EDI
		MOV ECX, a
		XOR ECX, EDX
		ADD ECX, DWORD PTR DS : xx[48]
		LEA ECX, DWORD PTR DS : [EAX + ECX + 0x6ED9FBA1]
		MOV EAX, ECX
		SHR EAX, 0x11
		SHL ECX, 0x0F
		OR EAX, ECX
		MOV ECX, a
		XOR ECX, EAX
		ADD ECX, DWORD PTR DS : xx[8]
		LEA EDX, DWORD PTR DS : [EDX + ECX + 0x6ED9FBA1]
		MOV ECX, EDX
		SHR ECX, 0x1D
		SHL EDX, 3
		OR ECX, EDX
		MOV EDX, EDI
		XOR EDX, EAX
		XOR EDX, ECX
		ADD EDX, DWORD PTR DS : xx[40]
		LEA EBX, DWORD PTR DS : [EBX + EDX + 0x6ED9FBA1]
		MOV EDX, EBX
		SHR EDX, 0x17
		SHL EBX, 9
		OR EDX, EBX
		MOV EBX, EDX
		MOV a, EDX
		XOR EBX, EAX
		XOR EBX, ECX
		ADD EBX, DWORD PTR DS : xx[24]
		LEA EDI, DWORD PTR DS : [EDI + EBX + 0x6ED9FBA1]
		MOV EBX, EDI
		SHR EBX, 0x15
		SHL EDI, 0x0B
		OR EBX, EDI
		XOR a, EBX
		MOV EDI, a
		XOR EDI, ECX
		ADD EDI, DWORD PTR DS : xx[56]
		LEA EDI, DWORD PTR DS : [EAX + EDI + 0x6ED9FBA1]
		MOV EAX, EDI
		SHR EAX, 0x11
		SHL EDI, 0x0F
		OR EAX, EDI
		MOV EDI, a
		XOR EDI, EAX
		ADD EDI, DWORD PTR DS : xx[4]
		LEA EDI, DWORD PTR DS : [ECX + EDI + 0x6ED9FBA1]
		MOV ECX, EDI
		SHR ECX, 0x1D
		SHL EDI, 3
		OR ECX, EDI
		MOV EDI, EBX
		XOR EDI, EAX
		XOR EDI, ECX
		ADD EDI, DWORD PTR DS : xx[36]
		LEA EDX, DWORD PTR DS : [EDX + EDI + 0x6ED9FBA1]
		MOV EDI, EDX
		SHR EDI, 0x17
		SHL EDX, 9
		OR EDI, EDX
		MOV EDX, EDI
		MOV a, EDI
		XOR EDX, EAX
		XOR EDX, ECX
		ADD EDX, DWORD PTR DS : xx[20]
		LEA EBX, DWORD PTR DS : [EBX + EDX + 0x6ED9FBA1]
		MOV EDX, EBX
		SHR EDX, 0x15
		SHL EBX, 0x0B
		OR EDX, EBX
		XOR a, EDX
		MOV EBX, a
		XOR EBX, ECX
		ADD EBX, DWORD PTR DS : xx[52]
		LEA EBX, DWORD PTR DS : [EAX + EBX + 0x6ED9FBA1]
		MOV EAX, EBX
		SHR EAX, 0x11
		SHL EBX, 0x0F
		OR EAX, EBX
		MOV EBX, a
		XOR EBX, EAX
		ADD EBX, DWORD PTR DS : xx[12]
		LEA EBX, DWORD PTR DS : [ECX + EBX + 0x6ED9FBA1]
		MOV ECX, EBX
		SHR ECX, 0x1D
		SHL EBX, 3
		OR ECX, EBX
		MOV EBX, EDX
		XOR EBX, EAX
		ADD DWORD PTR DS : State0, ECX
		XOR EBX, ECX
		ADD EBX, DWORD PTR DS : xx[44]
		LEA EDI, DWORD PTR DS : [EDI + EBX + 0x6ED9FBA1]
		MOV EBX, EDI
		SHR EBX, 0x17
		SHL EDI, 9
		OR EBX, EDI
		MOV EDI, EBX
		ADD DWORD PTR DS : State3, EBX
		XOR EDI, EAX
		XOR EDI, ECX
		ADD EDI, DWORD PTR DS : xx[28]
		LEA EDX, DWORD PTR DS : [EDX + EDI + 0x6ED9FBA1]
		MOV EDI, EDX
		SHR EDI, 0x15
		SHL EDX, 0x0B
		OR EDI, EDX
		MOV EDX, EBX
		XOR EDX, EDI
		ADD DWORD PTR DS : State2, EDI
		XOR EDX, ECX
		ADD EDX, DWORD PTR DS : xx[60]
		LEA EAX, DWORD PTR DS : [EAX + EDX + 0x6ED9FBA1]
		MOV ECX, EAX
		SHR ECX, 0x11
		SHL EAX, 0x0F
		OR ECX, EAX
		LEA EAX, DWORD PTR DS : xx[0]
		ADD DWORD PTR DS : State1, ECX
		POPAD
	}

	state[0] = State0;
	state[1] = State1;
	state[2] = State2;
	state[3] = State3;
	/* Zeroize sensitive information.

  */
	MD5_memset((unsigned char*)xx, 0, sizeof(xx));
}

/* Encodes input (UINT4) into output (unsigned char). Assumes len is
  a multiple of 4 */
static void Encode(unsigned char* output, UINT4* input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char)(input[i] & 0xff);
		output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
	}
}

/* Decodes input (unsigned char) into output (UINT4). Assumes len is
  a multiple of 4 */
static void Decode(UINT4* output, unsigned char* input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((UINT4)input[j]) | (((UINT4)input[j + 1]) << 8) | (((UINT4)input[j + 2]) << 16) | (((UINT4)input[j + 3]) << 24);
}

/* Note: Replace "for loop" with standard memcpy if possible */
static void MD5_memcpy(unsigned char* output, unsigned char* input, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		output[i] = input[i];
}

/* Note: Replace "for loop" with standard memset if possible */
static void MD5_memset(unsigned char* output, int value, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		((char*)output)[i] = (char)value;
}

unsigned char* MD5_string(std::string input)
{
	MD5Context* context = new MD5Context;
	MD5Init(context);
	MD5Update(context, (unsigned char*)input.data(), input.length());
	MD5Final(md5Digest, context);

	return md5Digest;
}

std::string MD5_Print(unsigned char* MD5Digest)
{
	char digits[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	std::string result;
	for (int i = 0; i < 16; i++)
		result = result + digits[(MD5Digest[i] >> 4) & 0x0f] + digits[MD5Digest[i] & 0x0f];
	return result;
}