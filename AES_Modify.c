/*
	Author: Kunal Baweja
	Date: 04-Jan-2014
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <vector>

void handleErrors()
{
	printf("Some error occured\n");
}

unsigned char *encrypt(unsigned char *key,
					   unsigned char *plaintext,
					   size_t plaintext_len,
					   unsigned char *iv,
					   unsigned char *aad,
					   int aad_len,
					   size_t &ciphertext_len)
{
	int len;

	unsigned char *tag = (unsigned char *)malloc(1024 * sizeof(unsigned char));

	EVP_CIPHER_CTX *ctx;
	unsigned char *ciphertext =
		(unsigned char *)malloc(1048576 * sizeof(unsigned char));

	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
	}

	// Set cipher type and mode
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL))
	{
	}

	// Initialise key and IV
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
	{
	}

	// Zero or more calls to specify any AAD
	EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

	// Encrypt plaintext
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	{
	}

	ciphertext_len = len;

	// Output encrypted block
	// Finalise: note get no output for Octon
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
	}

	// Get tag
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
	{
	}

	EVP_CIPHER_CTX_free(ctx);

	for (size_t i = 0; i < 16; i++)
	{
		ciphertext[ciphertext_len + i] = tag[i];
	}

	ciphertext_len += 16;

	free(tag);

	return ciphertext;
}

int decrypt(unsigned char *key,
			unsigned char *ciphertext,
			int ciphertext_len,
			unsigned char *iv,
			size_t iv_length,
			unsigned char *aad,
			int aad_len,
			unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	int tag_offset = ciphertext_len - 16;

	// set up to Decrypt AES 256 GCM

	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
	}

	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL))
	{
	}

	// set the key and ivec
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_length, NULL);
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	{
	}

	// Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier
	// requires the tag before any AAD or ciphertext
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
							 ciphertext + tag_offset))
	{
	}

	// add optional AAD (Additional Auth Data)
	if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
	{
	}

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, tag_offset))
	{
	}

	plaintext_len = len;

	int rv = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
	if (1 != rv)
	{
		plaintext_len = -1;
	}
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

int main(int argc, char **argv)
{
	unsigned char frame[1024], key[32], ciphertext[1024 + EVP_MAX_BLOCK_LENGTH], tag[100], pt[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char iv[16];
	unsigned char aad[16] = "abcdefghijklmnop"; // dummy
	int k;

	printf("Enter key: ");
	scanf("%s", key);

	/* generate encryption key from user entered key */
	if (!PKCS5_PBKDF2_HMAC_SHA1(key, strlen(key), NULL, 0, 1000, 32, key))
	{
		printf("Error in key generation\n");
		exit(1);
	}

	/* get plaintext input */
	printf("Enter plaintext: ");
	scanf("%s", frame);

	/* generate random IV */
	// while (!RAND_bytes(iv, sizeof(iv)))
	// 	;

	uint8_t unencrypted_bytes = 10;

	unsigned char *encrypted_frame =
		(unsigned char *)malloc(1048576 * sizeof(unsigned char));

	vector<uint8_t> iv = {74, 70, 114, 97, 109, 101,
						  69, 110, 99, 114, 121, 112};

	unsigned char plaintext[frame.size() - unencrypted_bytes];

	vector<uint8_t> frame_header;
	for (size_t i = 0; i < unencrypted_bytes; i++)
	{
		encrypted_frame[i] = frame[i];
		frame_header.push_back(encrypted_frame[i]);
	}


	/* encrypt the text and print on STDOUT */
	unsigned char *ciphertext =
		encrypt(&key[0], plaintext, frame.size() - unencrypted_bytes,
				&iv[0], &frame_header[0], unencrypted_bytes, ciphertext_len);

	// k = encrypt(plaintext, strlen(plaintext), aad, sizeof(aad), key, iv, ciphertext, tag);
	printf("Chipertext is %s\n", ciphertext);
	

	// /* decrypt the text and print on STDOUT */
	// k = decrypt(ciphertext, k, aad, sizeof(aad), tag, key, iv, pt);
	// if (k > 0)
	// {
	// 	pt[k] = '\0';
	// 	printf("%s\n", pt);
	// }
	// else
	// 	printf("Unreliable Decryption, maybe the encrypted data was tampered\n");
	return 0;
}