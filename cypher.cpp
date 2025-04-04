// fst.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <stdexcept>

using namespace std;

#include "floodsquare.h"

bool read_binary_file(const std::string filename, uint8_t** idata, uint32_t *isize)
{
    // binary mode is only for switching off newline translation
    std::ifstream file(filename, std::ios::binary);

    if (!file.good())
        throw exception("File not found");

    file.unsetf(std::ios::skipws);

    std::streampos file_size;
    file.seekg(0, std::ios::end);
    file_size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> vec;
    vec.reserve(file_size);
    vec.insert(vec.begin(),
        std::istream_iterator<uint8_t>(file),
        std::istream_iterator<uint8_t>());

    *isize = (uint32_t)vec.size();
    *idata = (uint8_t*) new uint8_t[vec.size()];
    std::copy(vec.begin(), vec.end(), *idata);

    return true;
}

bool write_binary_file(const std::string filename, unsigned char* pucData, uint32_t ulDataSize)
{
    // Save data to file
    std::ofstream file(filename, std::ios::out | std::ios::binary);

    if (file.good()) {

        file.write((const char*)pucData, ulDataSize);

        file.close();
        return true;
    }

    return false;
}

void floodsquare_encrypt(std::string fnIn, std::string fnOut, std::string sKey)
{
    CFloodSquare floodsquare;
    uint8_t *edata, *idata;
    uint32_t esize, isize;

    read_binary_file(fnIn, &idata, &isize);

    floodsquare.Encrypt(idata, isize, sKey, &edata, &esize, CFloodSquare::evSaltNone, true);
   
    write_binary_file(fnOut, edata, esize);
}

void floodsquare_decrypt(std::string fnIn, std::string fnOut, std::string sKey)
{
    CFloodSquare floodsquare;
    uint8_t *ddata, *idata;
    uint32_t dsize, isize;

    read_binary_file(fnIn, &idata, &isize);

    floodsquare.Decrypt(idata, isize, sKey, &ddata, &dsize, CFloodSquare::evSaltNone);

    if(dsize > isize)
        throw exception("Decrypion error");

    write_binary_file(fnOut, ddata, dsize);
}

int main()
{
    try {
        floodsquare_encrypt("./Lorem_ipsum.pdf", "./Lorem_ipsum_encrypted.bin", "e1f020c91178264867f3cb99f422cb3708db08a1736aa681558a5151ba2554bb");
        floodsquare_decrypt("./Lorem_ipsum_encrypted.bin", "./Lorem_ipsum_decrypted.pdf", "e1f020c91178264867f3cb99f422cb3708db08a1736aa681558a5151ba2554bb");
    }
    catch (const exception& e) {
        cerr << e.what() << endl;
    }
    catch (...) {
        cerr << "Unknown error" << endl;
    }

    return 0;
}


