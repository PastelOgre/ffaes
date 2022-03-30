/*
 * ffaes.h
 *
 *  Created on: Apr 19, 2018
 *      Author: Jesse Wang
 *
 *      Usage note: Ciphertext and plaintext arguments may point to the same buffer.
 */

#ifndef FFAES_H_
#define FFAES_H_

#include <stdint.h>

typedef struct FFAES ffaes_t;

#define FFAES128 0
#define FFAES192 1
#define FFAES256 2

#define FFAES_MAX_CIPHER_PADDING_SIZE 20

#ifdef __cplusplus
extern "C" {
#endif

//Fills necessary tables for AES cryptography. If this is not called, the first key created
//will call it and take a little longer to create.
void ffaes_init();

//Creates a key to be used in decryption and encryption. Pass FFAES128, FFAES192, or FFAES256 as mode.
ffaes_t* ffaes_create(const void* key, int mode);

void ffaes_destroy(ffaes_t* key);

//Encrypt and decrypt 16 byte blocks. The input and output can point to the same buffer.
void ffaes_encrypt_block(ffaes_t* key, void* cipher_output, void* plaintext_input);
void ffaes_decrypt_block(ffaes_t* key, void* plaintext_output, void* cipher_input);

//Encrypts size_bytes from plaintext_input to cipher_output in ECB mode. Must be multiple of 16.
void ffaes_encrypt(ffaes_t* key, void* cipher_output, void* plaintext_input, int size_bytes);

//Decrypts size_bytes from cipher_input to plaintext_output in ECB mode. Must be multiple of 16.
void ffaes_decrypt(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes);

//Encrypts size_bytes from plaintext_input to cipher_output in ECB mode. Must be multiple of 16.
void ffaes_encrypt_cbc(ffaes_t* key, void* cipher_output, void* plaintext_input, int size_bytes, const void* iv);

//Decrypts size_bytes from cipher_input to plaintext_output in ECB mode. Must be multiple of 16.
void ffaes_decrypt_cbc(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes, const void* iv);

//In the padded encryption functions, the output size will be different than the input size, but the input no longer
//has to be a multiple of 16. However, the cipher message will always be at least 4 bytes greater than the plaintext message.
//The cipher message is also at most FFAES_MAX_CIPHER_PADDING_SIZE bytes larger than the plaintext message. Another drawback is that
//the output buffer pointer can no longer by the same as the input buffer pointer. Non-padded functions allow this.
int ffaes_get_cbc_padded_cipher_size(int plaintext_size);

//Returns the number of bytes written to cipher_output.
int ffaes_encrypt_cbc_padded(ffaes_t* key, void* cipher_output, void* cipher_input, int size_bytes, const void* iv);

//Decryption should be fine as long as plaintext_output buffer is at least the same size as the cipher_input.
//Returns the size in bytes of the original plaintext.
int ffaes_decrypt_cbc_padded(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes, const void* iv);

#ifdef __cplusplus
}
#endif

#endif /* FFAES_H_ */
