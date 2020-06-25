#pragma once
#include <iostream>

typedef uint32_t UINT4;


struct MD5Context
{
	UINT4 state[4];                                   /* state (ABCD) */
	UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
};

static unsigned char md5Digest[16];

void MD5Transform(UINT4 state[], unsigned char block[]);
void Encode(unsigned char*, UINT4*, unsigned int);
void Decode(UINT4* output, unsigned char* input, unsigned int len);
void MD5_memcpy(unsigned char* output, unsigned char* input, unsigned int len);
void MD5_memset(unsigned char* output, int value, unsigned int len);
unsigned char* MD5_string(std::string input);
std::string MD5_Print(unsigned char* MD5Digest);