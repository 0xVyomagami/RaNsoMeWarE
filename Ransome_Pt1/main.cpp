#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>

using namespace std;

BOOL EncFile(const char* inputFilePath, const char* outputFile, const BYTE* key, DWORD keyLength) {
    HANDLE hInputFile = CreateFileA(inputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hOutputFile = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hInputFile == INVALID_HANDLE_VALUE || hOutputFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptHashData(hHash, key, keyLength, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    const DWORD bufferSize = 1024;
    BYTE buffer[bufferSize];
    DWORD bytesRead, bytesWritten;
    BOOL success = TRUE;

    while (TRUE) {
        if (!ReadFile(hInputFile, buffer, bufferSize, &bytesRead, NULL) || bytesRead == 0) {
            break; // End of file or read error
        }

        if (!CryptEncrypt(hKey, NULL, FALSE, 0, buffer, &bytesRead, bufferSize)) {
            success = FALSE;
            break;
        }

        if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesRead != bytesWritten) {
            success = FALSE;
            break;
        }
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    CloseHandle(hInputFile);
    CloseHandle(hOutputFile);

    return success;
}


BOOL DecFile(const char* inputFilePath, const char* outputFile, const BYTE* key, DWORD keyLength) {
    HANDLE hInputFile = CreateFileA(inputFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hOutputFile = CreateFileA(outputFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hInputFile == INVALID_HANDLE_VALUE || hOutputFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptHashData(hHash, key, keyLength, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hCryptProv, 0);
        CloseHandle(hInputFile);
        CloseHandle(hOutputFile);
        return FALSE;
    }

    const DWORD bufferSize = 1024;
    BYTE buffer[bufferSize];
    DWORD bytesRead, bytesWritten;
    BOOL success = TRUE;

    while (TRUE) {
        if (!ReadFile(hInputFile, buffer, bufferSize, &bytesRead, NULL) || bytesRead == 0) {
            break; // End of file or read error
        }

        if (!CryptDecrypt(hKey, NULL, FALSE, 0, buffer, &bytesRead)) {
            success = FALSE;
            break;
        }

        if (!WriteFile(hOutputFile, buffer, bytesRead, &bytesWritten, NULL) || bytesRead != bytesWritten) {
            success = FALSE;
            break;
        }
    }

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hCryptProv, 0);
    CloseHandle(hInputFile);
    CloseHandle(hOutputFile);

    return success;
}


BOOL CompareKeys(const BYTE* key1, const BYTE* key2, DWORD keyLength)
{
	for (DWORD i = 0;i < keyLength;++i)
	{
		if (key1[i] != key2[i])
		{
			return FALSE;
		}
	}
		return TRUE;
}

int main()
{
	const char* inputFilePath = "D:\\dummy\\hell_o.txt";
	const char* encryptedFilePath = "D:\\dummy\\encrypted_file.txt";
	const char* decryptedFilePath = "D:\\dummy\\decrypted_file.txt";

	const BYTE storedKey[] = { 0x01, 0xAB, 0x3F, 0x8D, 0x5E }; // Stored key
	DWORD keyLength = sizeof(storedKey);

	if (EncFile(inputFilePath, encryptedFilePath, storedKey, keyLength))
	{
		cout << "File Encrypted Failed!" << endl;
    }
    /*else {
        cout << "Encryption falied!" << endl;
        return 1;
    }*/


	BYTE* userProvidedKey = new BYTE[keyLength];
	cout << "Enter the key (5 bytes in hexadecimal format, e.g., 01 AB 3F 8D 5E): " << endl;

	for (DWORD i = 0;i < keyLength; ++i)
	{
		int byte;
		cin >> hex >> byte;
		userProvidedKey[i] = static_cast <BYTE>(byte);
	}

	try {
		if (CompareKeys(userProvidedKey, storedKey, keyLength))
		{
			if (DecFile(encryptedFilePath, decryptedFilePath, storedKey, keyLength))
			{
				cout << "File decrypted successfully! \n";
			}
			else {
				cout << "Decryption failed.\n";
			}
		}
		else {
			throw std::runtime_error("Provided key does not match the stored key.\n");
		}
	}
	catch (const exception& e) {
		cerr << "ERROR: " << e.what() << endl;
	}
	delete[] userProvidedKey;
	return 0;
}