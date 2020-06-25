#include <iostream>
#include <string>
#include <sstream>
#include <conio.h>

using namespace std;

uint32_t table[6] = { 0x34, 0x78, 0x12, 0xFE, 0xDB, 0x78 };

int main()
{
	string passHex = "4D11628EBE1D";
	string key;

	for (int i = 0; i < passHex.length(); i += 2)
	{
		stringstream ss;
		ss << std::hex << passHex.substr(i, 2);

		int tmp = 0;
		ss >> tmp;

		key += ((char)tmp ^ table[i / 2]);
	}

	cout << "Key: " << key;
	_getch();
}