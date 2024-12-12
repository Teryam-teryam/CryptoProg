#include <iostream>
#include <vector>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <fstream>
using namespace CryptoPP;
using namespace std;

int main ()
{
   	std::string name = "text.txt";
   	std::string input = "";
   	std::string output = "";
    Weak::MD5 hash;
		
		ifstream file(name, ios::binary);
    if (!file.is_open())
    {
        cerr << "Ошибка открытия файла" << endl;
        exit(EXIT_FAILURE);
    }
	
    while (!file.eof())
      {
      		getline(file, input);
      		StringSource(input, true,             // источник-стока
                 new HashFilter(hash,       // фильтр-"хеширователь"
                                new HexEncoder(     // кодировщик в строку цифр                            
                                    new StringSink(output))));  // строка-приемник
      		    	
      }
      std::cout << output << std::endl;
    return 0;
}
