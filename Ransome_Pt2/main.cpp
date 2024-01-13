#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>

using namespace std;

BOOL EncFile(const char* inputFilePath, const BYTE* key, DWORD keyLength)
{
	HANDLE hInputFile = CreateFileA(inputFilePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hInputFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hInputFile);
		return FALSE;
	}

	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;

	if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
	{
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptHashData(hHash, key, keyLength, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}

	const DWORD bufferSize = 1024;
	BYTE buffer[bufferSize];
	DWORD bytesRead, bytesWritten;
	BOOL success = TRUE;

	while (ReadFile(hInputFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
	{
		if (!CryptEncrypt(hKey, NULL, FALSE, 0, buffer, &bytesRead, sizeof(buffer)))
		{
			success = TRUE;
			break;
		}
		SetFilePointer(hInputFile, -static_cast<LONG>(bytesRead), NULL, FILE_CURRENT);
		WriteFile(hInputFile, buffer, bytesRead, &bytesWritten, nullptr);
	}

	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
	CloseHandle(hInputFile);

	return success;
}

BOOL DecFile(const char* inputFilePath, const BYTE* key, DWORD keyLength)
{
	HANDLE hInputFile = CreateFileA(inputFilePath, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (hInputFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hInputFile);
		return FALSE;
	}

	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
	HCRYPTHASH hHash;

	if (!CryptAcquireContext(&hCryptProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash))
	{
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptHashData(hHash, key, keyLength, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}

	if (!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hCryptProv, 0);
		CloseHandle(hInputFile);
		return FALSE;
	}
	
	const DWORD bufferSize = 1024;
	BYTE buffer[bufferSize];
	DWORD bytesRead, bytesWritten;
	BOOL success = TRUE;

	while (ReadFile(hInputFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
	{
		if (!CryptDecrypt(hKey, NULL, FALSE, 0, buffer, &bytesRead))
		{
			success = FALSE;
			break;
		}
		SetFilePointer(hInputFile, -static_cast<LONG>(bytesRead), NULL, FILE_CURRENT);
		WriteFile(hInputFile, buffer, bytesRead, &bytesWritten, nullptr);
	}

	CryptDestroyKey(hKey);
	CryptDestroyHash(hHash);
	CryptReleaseContext(hCryptProv, 0);
	CloseHandle(hInputFile);

	return success;
}


BOOL CompareKeys(const BYTE* key1, const BYTE* key2, DWORD keyLength)
{
	for (DWORD i = 0; i < keyLength; ++i)
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
	const BYTE storedKey[] = { 0x01, 0xAB, 0x3F, 0x8D, 0x5E };
	DWORD keyLength = sizeof(storedKey);

	if (EncFile(inputFilePath, storedKey, keyLength))
	{
		cout << "File encrypted successfully!" << endl;
	}
	else {
		cout << "Encryption Failed!" << endl;
		return 1;
	}

	BYTE* userProvidedKey = new BYTE[keyLength];
	cout << "Enter the key (5 bytes in hexadecimal format, e.g., 01 AB 3F 8D 5E): " << endl;

	for (DWORD i = 0; i < keyLength; ++i)
	{
		int byte;
		cin >> hex >> byte;
		userProvidedKey[i] = static_cast <BYTE>(byte);
	}

	try {
		if (CompareKeys(userProvidedKey, storedKey, keyLength))
		{
			if (DecFile(inputFilePath, userProvidedKey, keyLength))
			{
				cout << "File decrypted successfully!" << endl;
			}
			else {
				cout << "Decryption failed.\n";
			}
		}
		else {
			throw std::runtime_error("Provided key does not match the stored key!\n");
		}
	}
	catch (const exception& e)
	{
		cerr << "ERROR: " << e.what() << endl;
	}

	delete[] userProvidedKey;

	return 0;
}