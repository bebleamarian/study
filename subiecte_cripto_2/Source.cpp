#ifndef _CRT_SECURE_NO_WARNINGS

#define _CRT_SECURE_NO_WARNINGS

#endif // !_CRT_SECURE_NO_WARNINGS

#include<stdio.h>
#include<openssl\aes.h>
#include<openssl\sha.h>
#include<openssl\rand.h>
#include<conio.h>
#include<string.h>


#define ENCRYPT 0
#define DECRYPT 1


char* GetPassword()
{
	char character;
	char password[30];
	int index = 0;
	printf("introduceti parola: ");

	character = _getch();
	while (character != 13)
	{
		password[index++] = character;
		printf("*");
		character = _getch();
	}
	password[index] = '\0';

	return password;
}

int _add_padding(unsigned char** data, int &dataLen, int blockSize)
{
	//determin numarul de octeti necesari pt padding
	int padblk_nr = blockSize - (dataLen % blockSize);

	//daca ultimul bloc este complet atunci mai aloc memorie pentru un bloc intreg cu fiecare octet 0x10
	if (padblk_nr == 0)
	{
		dataLen += blockSize;
		(*data) = (unsigned char*)realloc(*data, dataLen + 1);
		if (*data == NULL)
			return 0;

		for (int i = 1; i <= blockSize; i++)
			(*data)[dataLen - i] = blockSize;
	}

	else
		//altfel aloc memorie pt inca padblk_nr octeti cu valoare padblk_nr
	{
		dataLen += padblk_nr;
		(*data) = (unsigned char*)realloc(*data, dataLen + 1);
		if (*data == NULL)
			return  0;

		for (int i = 1; i <= padblk_nr; i++)
			(*data)[dataLen - i] = padblk_nr;
	}
	return 1;
}


unsigned char* aes_256_cbc(unsigned char* in, unsigned char* iv, AES_KEY* key, bool mode)
{
	int	offset = 0;
	int len = strlen((char*)in);
	unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
	unsigned char* out = (unsigned char*)malloc(len * sizeof(unsigned char) + 1);
	memset(out, 0, len + 1);

	if(mode==ENCRYPT)
		while (offset < len)
		{
			memcpy(inblk, in + offset, AES_BLOCK_SIZE);

			for (int i = 0; i < AES_BLOCK_SIZE; i++)
				inblk[i] = inblk[i] ^ iv[i];

			AES_encrypt(inblk, outblk, key);
			memcpy(iv, outblk, AES_BLOCK_SIZE );

			memcpy(out + offset, outblk, AES_BLOCK_SIZE);
			offset += AES_BLOCK_SIZE;
		}
	else
		while (offset < len)
		{
			memcpy(inblk, in + offset, AES_BLOCK_SIZE);

			AES_decrypt(inblk, outblk, key);
			
			for (int i = 0; i < AES_BLOCK_SIZE; i++)
				outblk[i] = outblk[i] ^ iv[i];

			memcpy(iv, inblk, AES_BLOCK_SIZE );
			memcpy(out + offset, outblk, AES_BLOCK_SIZE);
			offset += AES_BLOCK_SIZE;
		}

	return out;
}



int encrypt(const char* file_name, const char* encrypted_file_name)
{
	#pragma region variables

	int iv_len = 16;
	int key_len = 32;
	int plaintext_len = iv_len + key_len;

	AES_KEY aes_key;
	FILE* file_to_encrypt;
	FILE* encrypted_file;
	
	char *pass = GetPassword();
	unsigned char* hash = (unsigned char*)malloc(SHA512_DIGEST_LENGTH * sizeof(unsigned char) + 1);
	unsigned char* masterKey = (unsigned char*)malloc(key_len * sizeof(unsigned char) + 1);
	unsigned char* masterIv = (unsigned char*)malloc(iv_len * sizeof(unsigned char) + 1);
	unsigned char* Key = (unsigned char*)malloc(key_len * sizeof(unsigned char) + 1);
	unsigned char* Iv = (unsigned char*)malloc(iv_len * sizeof(unsigned char) + 1);
	unsigned char* plaintext = (unsigned char*)malloc((key_len + iv_len) * sizeof(unsigned char) + 1);

	#pragma endregion

	//sets the master key and master iv from password and get the Key and Iv with random bytes
	#pragma region set key and iv

	SHA512((unsigned char*)pass, strlen(pass), hash);
	memset(masterKey, 0, key_len + 1);
	memset(masterIv, 0, iv_len + 1);

	memcpy(masterIv, hash, iv_len);
	memcpy(masterKey, hash + iv_len, key_len);

	RAND_bytes(Key, 32);
	RAND_bytes(Iv, 16);

	
	#pragma endregion

	//read data from file
	#pragma region read data from file

	file_to_encrypt = fopen(file_name, "rb");
	if (!file_to_encrypt)
	{
		printf("%s\n","eroare la deschiderea fisierului");	
		return 0;
	}

	fseek(file_to_encrypt, 0, SEEK_END);
	int file_size = ftell(file_to_encrypt);
	rewind(file_to_encrypt);
	unsigned char *buffer = (unsigned char*)malloc(file_size * sizeof(unsigned char) + 1);

	fread(buffer, file_size, 1, file_to_encrypt);
	
	buffer[file_size] = '\0';

	fclose(file_to_encrypt);	
		

	#pragma endregion

	memset(plaintext, 0, plaintext_len);
	memcpy(plaintext, Iv, iv_len);
	memcpy(plaintext + iv_len, Key, key_len + 1);

	
	encrypted_file = fopen(encrypted_file_name, "wb");

	
	_add_padding(&plaintext, plaintext_len, AES_BLOCK_SIZE);
	_add_padding(&buffer, file_size, AES_BLOCK_SIZE);
	
	plaintext[plaintext_len] = '\0';
	buffer[file_size] = '\0';
	
	AES_set_encrypt_key(masterKey, key_len * 8, &aes_key);
	fwrite(aes_256_cbc(plaintext, masterIv, &aes_key,ENCRYPT), plaintext_len, 1, encrypted_file);
	
	memset(masterKey, 0, key_len + 1);
	free(masterKey);

	AES_set_encrypt_key(Key, key_len * 8, &aes_key);									//setez cheia ca si Key 
	fwrite(aes_256_cbc(buffer, Iv, &aes_key,ENCRYPT), file_size, 1, encrypted_file);

	printf("\n\n S-a realizat criptarea fisierului %s in fisierul %s \n\n",file_name,encrypted_file_name);

	fclose(encrypted_file);
	free(plaintext);
	free(masterIv);
	free(buffer);
	free(Iv);
	free(Key);

	return plaintext_len;
}


void decrypt(const char* encrypted_file_name, const char* decrypted_file_name,int len_of_encrypted_key_and_iv)
{
	FILE* file_to_decrypt;
	FILE *decrypted_file;
	AES_KEY key;
	char* pass = GetPassword();
	int iv_len = 16;
	int key_len = 32;

	unsigned char* hash = (unsigned char*)malloc(SHA512_DIGEST_LENGTH * sizeof(unsigned char) + 1);
	unsigned char* Iv = (unsigned char*)malloc(iv_len * sizeof(unsigned char) + 1);
	unsigned char* Key = (unsigned char*)malloc(key_len * sizeof(unsigned char) + 1);
	
	SHA512((unsigned char*)pass, strlen(pass), hash);
	memset(Iv, 0, iv_len + 1);
	memset(Key, 0, key_len + 1);

	memcpy(Iv, hash, iv_len);
	memcpy(Key, hash + iv_len, key_len);

	
	memset(hash, 0, SHA512_DIGEST_LENGTH + 1);

	file_to_decrypt = fopen(encrypted_file_name,"rb");
	if (!file_to_decrypt)
	{
		printf("%s\n","eroare la deshiderea fisierului pentru decriptare");
		return;
	}

	fseek(file_to_decrypt,0,SEEK_END);
	int file_size = ftell(file_to_decrypt);
	rewind(file_to_decrypt);
	int buffer_len = file_size - len_of_encrypted_key_and_iv;

	unsigned char* iv_and_key = (unsigned char*)malloc(len_of_encrypted_key_and_iv * sizeof(unsigned char) + 1);
	unsigned char* buffer = (unsigned char*)malloc(buffer_len * sizeof(unsigned char) + 1);
	unsigned char* out= (unsigned char*)malloc(len_of_encrypted_key_and_iv * sizeof(unsigned char) + 1);

	fread(iv_and_key,len_of_encrypted_key_and_iv,1,file_to_decrypt);					//citesc exact len_of_encrypted_key_and_iv penrtu a decripta cheia si iv-ul cu care a fost criptat continutul fisierului
	fread(buffer, buffer_len, 1, file_to_decrypt);										// de aici incepe continutul fisierului

	iv_and_key[len_of_encrypted_key_and_iv] = '\0';
	buffer[buffer_len] = '\0';

	fclose(file_to_decrypt);

	AES_set_decrypt_key(Key, key_len * 8, &key);
	out = aes_256_cbc(iv_and_key,Iv,&key,DECRYPT);

	memset(Iv, 0, iv_len + 1);
	memset(Key, 0, key_len + 1);

	memcpy(Iv,out,iv_len);
	memcpy(Key, out + iv_len, key_len);


	free(out);

	out= (unsigned char*)malloc(buffer_len * sizeof(unsigned char) + 1);
	AES_set_decrypt_key(Key, key_len * 8, &key);
	out = aes_256_cbc(buffer, Iv, &key, DECRYPT);

	decrypted_file = fopen(decrypted_file_name, "wb");
	fwrite(out, buffer_len, 1, decrypted_file);


	printf("\n\n S-a realizat decriptarea fisierului %s in fisierul %s \n\n", encrypted_file_name, decrypted_file_name);

	fclose(decrypted_file);
	free(hash);
	free(Iv);
	free(Key);
	free(iv_and_key);
	free(buffer);

}



int main()
{
	const char* file_name = "salut.txt";
	const char* encrypted_file_name = "encrypted.txt";
	const char* decrypted_file_name = "decrypted.txt";

	int len = encrypt(file_name, encrypted_file_name);		// returnez cati oteti din fisierul criptat reprezinta chaia si iv-ul 
															// criptate pentru a sti cat sa citesc la decriptare
	decrypt(encrypted_file_name, decrypted_file_name,len);

	system("pause");

	return 1;
}