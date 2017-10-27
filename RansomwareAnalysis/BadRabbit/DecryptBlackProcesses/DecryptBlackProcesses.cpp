/* Bad Rabbit blacklist process hash finder
   NioGuard Security Lab, 2017
   Author: Alexander Adamov
   Email : ada@nioguard.com
*/

#include <vector>
#include <fstream>
#include <sstream>

std::vector<std::string> vProcessNames; //store process names read from the file

int EncryptProcessName(const char* a1, size_t a2)
{
	unsigned int v2;
	unsigned int v3;
	unsigned int v4;
	char *v5;
	char v6;
	int v8;

	char v5_value;
	char a1_current_byte;

	v8 = 0x87654321;
	v2 = 0;
	do
	{
		v3 = 0;
		if (a2)
		{
			v4 = v2;
			do
			{
				v5 = (char *)&v8 + (v4 & 3);
				v5_value = *v5;
				a1_current_byte = *(char*)(a1 + v3);
				v6 = (v5_value ^ a1_current_byte);
				v6--;
				v3++;
				++v4;
				*v5 = v6;
			} while (v3 < a2);
		}
		++v2;
	} while (v2 < 3);
	return v8;
}

int ReadFile(char* fname)
{
	std::ifstream input(fname);
	std::string line;
	if (input.is_open())
	{
		while (input && std::getline(input, line))
		{
			if (line.length() == 0)continue;
			vProcessNames.push_back(line);
		}
		input.close();
		return 0;
	}
	else
		return 1;
	
	return 0;
}

int main(int argc, char* argv[])
{
	//process hashes from the Bad Rabbit Ransomware
	int black_hashes[6] = {
		0x4A241C3E,
		0x966D0415,
		0x0AA331620,
		0x0C8F10976,
		0x0E2517A14,
		0x0E5A05A00
	};
	const char* proc_name;
	
	//read process names from the file for hashing 
	if(!ReadFile("processes.txt"))
	for (size_t i = 0; i < vProcessNames.size(); i++)
	{
		proc_name = vProcessNames[i].c_str();
		int hash = EncryptProcessName(proc_name, strlen(proc_name));
		//printf("DEBUG: Hash for %s: %X\n", proc_name, hash);
		for (size_t i = 0; i < 6; i++)
		{
			if (hash == black_hashes[i])
				printf("Found: process %s: hash %X\n", proc_name, hash);
		}
	}
	
	return 0;
}

