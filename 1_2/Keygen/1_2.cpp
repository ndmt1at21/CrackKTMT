#include <iostream>
#include "md5.h"
#include "crc32.h"
#include <ctime>
#include <sstream>
#include <vector>
#include <conio.h>

const uint8_t BoxValue[8] = { 0xA6, 0x16, 0xAF, 0xFD, 0xD4, 0x07, 0x10, 0xF6 };

UINT4 strToInt(std::string hex)
{
	std::stringstream ss(hex);
	UINT4 result = 0;
	ss >> std::hex >> result;
	return result;
}

std::string intToHex(UINT4 a)
{
	std::string result;
	result.resize(9);
	sprintf_s((char*)result.data(), 9, "%08X", a);

	return result;
}

// Phát sinh 1 key mới, trong đó có 3 chữ trong chuỗi quy định, 2 số từ 0 - 9
std::string randomInputKey()
{
	std::string srcStr = "BDRQKPTVJI";
	std::string srcNum = "0123456789";
	std::string inputStr(5, '\0');

	int countChar = 0;
	while (countChar < 3)
	{
		int idx = rand() % 5;
		if (inputStr[idx] == '\0')
		{
			inputStr[idx] = srcStr[rand() % srcStr.length()];
			countChar++;
		}
	}

	int countNum = 0;
	while (countNum < 2)
	{
		int idx = rand() % 5;
		if (inputStr[idx] == '\0')
		{
			inputStr[idx] = srcNum[rand() % srcNum.length()];
			countNum++;
		}
	}

	return inputStr;
}

int main()
{
	srand(time(NULL));
	
	while (true)
	{
		std::string inputStr = randomInputKey();

		// Print key 1
		std::cout << "Key: " << inputStr << " - ";

		// Proccess
		unsigned char* md5 = MD5_string(inputStr);
		UINT4 A = 0;
		for (int i = 0; i < 4; i++)
		{
			UINT4 tmp = 0;

			// Copy mỗi 4 byte từ chuỗi vào biến tạm
			memcpy((void*)&tmp, (void*)&md5[i * 4], 4);

			// Mỗi lần lấy A xor với biến tạm
			A = A ^ tmp;
		}

		// Chuyển A sang định dạng hex string
		std::string hexTmp;
		std::stringstream ss;
		ss << std::hex << A;
		ss >> hexTmp;

		unsigned char hex[9] = { 0 };
		memcpy((void*)hex, hexTmp.c_str(), hexTmp.length());
		hex[hexTmp.length()] = '\0';

		for (int i = 0; i < hexTmp.length(); i++)
			hex[i] = (int(toupper(hex[i])) ^ BoxValue[i]);

		for (int i = 0; i < hexTmp.length(); i++)
			hex[i] = (int(toupper(hex[i] << i)) | int(hex[i]));

		// hash CRC32
		uint32_t crc = getStrCrc(hex, hexTmp.length());

		// Chuyển về dạng hex string
		ss.clear();
		ss << std::hex << crc;
		ss >> hex;
		
		// Print key 2
		for (int i = 0; i < 8; i++)
			hex[i] = toupper(hex[i]);
		std::cout << hex << std::endl;

		// Tiếp tục chương trình?
		std::cout << "Press space to get new key\n";
		std::cout << "Press any key to exit\n";

		int nContinue = _getch();
		

		
	}
}