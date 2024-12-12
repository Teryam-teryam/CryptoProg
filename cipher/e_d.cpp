#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;
using namespace std;

const int ITERATIONS = 1000;

SecByteBlock generateKeyFromPassword(const string& password)
{
    SecByteBlock key(AES::MAX_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(key, key.size(), 0, (const unsigned char*)password.data(), password.size(), (const unsigned char*)password.data(), password.size(), ITERATIONS);
    return key;
}

void encryptFile(const string& inputFile, const string& outputFile, const string& password)
{
    try
    {
        SecByteBlock key = generateKeyFromPassword(password);
        SecByteBlock iv(AES::BLOCKSIZE);

        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, iv.size());

        ofstream encryptedFile(outputFile, ios::binary);
        if (!encryptedFile.is_open())
        {
            throw runtime_error("Не удалось открыть файл для записи");
        }

        // Записываем инициализационный вектор в начало зашифрованного файла
        encryptedFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv);

        FileSource(inputFile.c_str(), true, new StreamTransformationFilter(encryptor, new FileSink(encryptedFile)));
    }
    catch (const Exception& e)
    {
        cerr << "Ошибка шифрования: " << e.what() << endl;
    }
}

void decryptFile(const string& inputFile, const string& outputFile, const string& password)
{
    try
    {
        SecByteBlock key = generateKeyFromPassword(password);
        SecByteBlock iv(AES::BLOCKSIZE);

        ifstream encryptedFile(inputFile, ios::binary);
        if (!encryptedFile.is_open())
        {
            throw runtime_error("Не удалось открыть файл для чтения");
        }

        // Считываем инициализационный вектор из начала зашифрованного файла
        encryptedFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

        CBC_Mode<AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv);

        FileSource(encryptedFile, true, new StreamTransformationFilter(decryptor, new FileSink(outputFile.c_str())));
    }
    catch (const Exception& e)
    {
        cerr << "Ошибка дешифрования: " << e.what() << endl;
    }
}

int main()
{
    string mode;
    string inputFile;
    string outputFile;
    string password;

    cout << "Введите режим (1 - шифрование/2 - дешифрование): ";
    cin >> mode;

    cout << "Введите входной файл: ";
    cin >> inputFile;

    cout << "Введите выходной файл: ";
    cin >> outputFile;

    cout << "Введите пароль: ";
    cin >> password;

    if (mode == "1")
    {
        encryptFile(inputFile, outputFile, password);
        cout << "Файл зашифрован успешно." << endl;
    }
    else if (mode == "2")
    {
        decryptFile(inputFile, outputFile, password);
        cout << "Файл дешифрован успешно." << endl;
    }
    else
    {
        cerr << "Недопустимый режим. Введите 'шифрование' или 'дешифрование'." << endl;
        return 1;
    }

    return 0;
}
