/*
 * ffaes.cpp
 *
 *  Created on: Apr 19, 2018
 *      Author: Jesse Wang
 */

#include "../ffaes.h"
#include "ffmem.h"
#include "fflog.h"
#include <string.h>
#include "ffbit.h"

static uint32_t enc0[256];
static uint32_t enc1[256];
static uint32_t enc2[256];
static uint32_t enc3[256];
static uint32_t dec0[256];
static uint32_t dec1[256];
static uint32_t dec2[256];
static uint32_t dec3[256];
static uint8_t sbox[256];
static uint8_t inverse_sbox[256];
static uint8_t rcon[15];
static uint8_t _init_complete = 0;

typedef struct FFAES
{
	uint8_t key_len;
	uint8_t num_rounds;
	uint8_t expanded_key_len;
	uint8_t* expanded_key;
	uint8_t* expanded_key_dec;
} ffaes_t;

static void ffaes_rotword(uint8_t* in, uint8_t* out)
{
	uint8_t k = *in;
	out[0] = in[1];
	out[1] = in[2];
	out[2] = in[3];
	out[3] = k;
}

static void ffaes_subword(uint8_t* in, uint8_t* out)
{
	int i;
	for(i=0;i<4;i++)
		*(out+i) = sbox[*(in+i)];
}

static void ffaes_xor_rcon(uint8_t* in, uint8_t* out, int r)
{
	*out = *in ^ rcon[r];
}

static void ffaes_xor_word(uint32_t* in1, uint32_t* in2, uint32_t* out)
{
	*out = *in1 ^ *in2;
}

static void ffaes_mix_column_inv(uint8_t* state)
{
	uint8_t* p = state;
	*((uint32_t*)p) =	dec0[sbox[p[0]]]^
			dec1[sbox[p[1]]]^
			dec2[sbox[p[2]]]^
			dec3[sbox[p[3]]];
	p+=4;
	*((uint32_t*)p) = dec0[sbox[p[0]]]^
			dec1[sbox[p[1]]]^
			dec2[sbox[p[2]]]^
			dec3[sbox[p[3]]];
	p+=4;
	*((uint32_t*)p) = dec0[sbox[p[0]]]^
			dec1[sbox[p[1]]]^
			dec2[sbox[p[2]]]^
			dec3[sbox[p[3]]];
	p+=4;
	*((uint32_t*)p) = dec0[sbox[p[0]]]^
			dec1[sbox[p[1]]]^
			dec2[sbox[p[2]]]^
			dec3[sbox[p[3]]];
}

static void ffaes_shiftrow_bytesub(uint8_t* state)
{
	uint8_t temp = sbox[state[1]];
	state[1] = sbox[state[5]];
	state[5] = sbox[state[9]];
	state[9] = sbox[state[13]];
	state[13] = temp;

	temp = sbox[state[2]];
	state[2] = sbox[state[10]];
	state[10] = temp;
	temp = sbox[state[6]];
	state[6] = sbox[state[14]];
	state[14] = temp;

	temp = sbox[state[15]];
	state[15] = sbox[state[11]];
	state[11] = sbox[state[7]];
	state[7] = sbox[state[3]];
	state[3] = temp;

	state[0] = sbox[state[0]];
	state[12] = sbox[state[12]];
	state[8] = sbox[state[8]];
	state[4] = sbox[state[4]];
}

static void ffaes_shiftrow_bytesub_inverse(uint8_t* state)
{
	uint8_t temp = inverse_sbox[state[13]];
	state[13] = inverse_sbox[state[9]];
	state[9] = inverse_sbox[state[5]];
	state[5] = inverse_sbox[state[1]];
	state[1] = temp;

	temp = inverse_sbox[state[10]];
	state[10] = inverse_sbox[state[2]];
	state[2] = temp;
	temp = inverse_sbox[state[14]];
	state[14] = inverse_sbox[state[6]];
	state[6] = temp;

	temp = inverse_sbox[state[3]];
	state[3] = inverse_sbox[state[7]];
	state[7] = inverse_sbox[state[11]];
	state[11] = inverse_sbox[state[15]];
	state[15] = temp;

	state[0] = inverse_sbox[state[0]];
	state[12] = inverse_sbox[state[12]];
	state[8] = inverse_sbox[state[8]];
	state[4] = inverse_sbox[state[4]];
}

void ffaes_init()
{
	//generate table for looking up multiplicative inverse
	uint8_t atable[256];
	uint8_t ltable[256];
	uint8_t mul_inverse[256];
	int c;
	uint8_t a = 1;
	uint8_t d;
	for(c=0;c<255;c++)
	{
		atable[c] = a;
		d = a & 0x80;
		a <<= 1;
		if(d == 0x80)
			a ^= 0x1b;
		a ^= atable[c];
		ltable[atable[c]] = c;
	}
	atable[255] = atable[0];
	ltable[0] = 0;
	for(c=0;c<256;c++)
	{
		if(c==0)
			mul_inverse[c] = 0;
		else
			mul_inverse[c] = atable[(255 - ltable[c])];
	}

	//generate s-box and inverse s-box
	for(c=0;c<256;c++)
	{
		uint8_t n, s, x;
		s = x = mul_inverse[c];
		for(n = 0; n < 4; n++)
		{
			s = (s << 1) | (s >> 7);
			x ^= s;
		}
		x ^= 99;
		sbox[c] = x;
		inverse_sbox[x] = c;
	}

	//build rcon table
	rcon[0] = 0x01;
	rcon[1] = 0x02;
	rcon[2] = 0x04;
	rcon[3] = 0x08;
	rcon[4] = 0x10;
	rcon[5] = 0x20;
	rcon[6] = 0x40;
	rcon[7] = 0x80;
	rcon[8] = 0x1B;
	rcon[9] = 0x36;
	rcon[10] = 0x6C;
	rcon[11] = 0xD8;
	rcon[12] = 0xAB;
	rcon[13] = 0x4D;
	rcon[14] = 0x9A;

	//build mix-column lookup tables
	for(c=0;c<256;c++)
	{
		uint32_t e1, e2 ,e3, d0E, d0B, d0D, d09;
		e1 = sbox[c];
		if(e1==0)
		{
			e2=0;
			e3=0;
		}
		else
		{
			e2 = ltable[sbox[c]]+ltable[2];
			if(e2 > 0xFF)
				e2 -= 0xFF;
			e2 = atable[e2];
			e3 = ltable[sbox[c]]+ltable[3];
			if(e3 > 0xFF)
				e3 -= 0xFF;
			e3 = atable[e3];
		}

		if(inverse_sbox[c]==0)
		{
			d0E=0;
			d0B=0;
			d0D=0;
			d09=0;
		}
		else
		{
			d0E = ltable[inverse_sbox[c]]+ltable[0x0E];
			if(d0E > 0xFF)
				d0E -= 0xFF;
			d0E = atable[d0E];
			d0B = ltable[inverse_sbox[c]]+ltable[0x0B];
			if(d0B > 0xFF)
				d0B -= 0xFF;
			d0B = atable[d0B];
			d0D = ltable[inverse_sbox[c]]+ltable[0x0D];
			if(d0D > 0xFF)
				d0D -= 0xFF;
			d0D = atable[d0D];
			d09 = ltable[inverse_sbox[c]]+ltable[0x09];
			if(d09 > 0xFF)
				d09 -= 0xFF;
			d09 = atable[d09];
		}

		//enc0 = 2,1,1,3
		((uint8_t*)(&enc0[c]))[0] = e2;
		((uint8_t*)(&enc0[c]))[1] = e1;
		((uint8_t*)(&enc0[c]))[2] = e1;
		((uint8_t*)(&enc0[c]))[3] = e3;

		//enc1 = 3,2,1,1
		((uint8_t*)(&enc1[c]))[0] = e3;
		((uint8_t*)(&enc1[c]))[1] = e2;
		((uint8_t*)(&enc1[c]))[2] = e1;
		((uint8_t*)(&enc1[c]))[3] = e1;

		//enc2 = 1,3,2,1
		((uint8_t*)(&enc2[c]))[0] = e1;
		((uint8_t*)(&enc2[c]))[1] = e3;
		((uint8_t*)(&enc2[c]))[2] = e2;
		((uint8_t*)(&enc2[c]))[3] = e1;

		//enc3 = 1,1,3,2
		((uint8_t*)(&enc3[c]))[0] = e1;
		((uint8_t*)(&enc3[c]))[1] = e1;
		((uint8_t*)(&enc3[c]))[2] = e3;
		((uint8_t*)(&enc3[c]))[3] = e2;

		//dec0 = E,9,D,B
		((uint8_t*)(&dec0[c]))[0] = d0E;
		((uint8_t*)(&dec0[c]))[1] = d09;
		((uint8_t*)(&dec0[c]))[2] = d0D;
		((uint8_t*)(&dec0[c]))[3] = d0B;

		//dec1 = B,E,9,D
		((uint8_t*)(&dec1[c]))[0] = d0B;
		((uint8_t*)(&dec1[c]))[1] = d0E;
		((uint8_t*)(&dec1[c]))[2] = d09;
		((uint8_t*)(&dec1[c]))[3] = d0D;

		//dec2 = D,B,E,9
		((uint8_t*)(&dec2[c]))[0] = d0D;
		((uint8_t*)(&dec2[c]))[1] = d0B;
		((uint8_t*)(&dec2[c]))[2] = d0E;
		((uint8_t*)(&dec2[c]))[3] = d09;

		//dec3 = 9,D,B,E
		((uint8_t*)(&dec3[c]))[0] = d09;
		((uint8_t*)(&dec3[c]))[1] = d0D;
		((uint8_t*)(&dec3[c]))[2] = d0B;
		((uint8_t*)(&dec3[c]))[3] = d0E;
	}
}

//Creates a key to be used in decryption and encryption. Pass FFAES128, FFAES192, or FFAES256 as mode.
ffaes_t* ffaes_create(const void* key, int mode)
{
	if(!_init_complete)
	{
		ffaes_init();
		_init_complete = 1;
	}
	if(mode != FFAES128 && mode != FFAES192 && mode != FFAES256)
	{
		fflog_debug_print("Use FFAES128, FFAES192, or FFAES256 defines for mode");
		return NULL;
	}
	ffaes_t* newkey = ffmem_alloc(ffaes_t);

	//expand key
	if(mode == FFAES128)
	{
		newkey->key_len = 16;
		newkey->expanded_key_len = 176;
		newkey->num_rounds = 9;
	}
	else if(mode == FFAES192)
	{
		newkey->key_len = 24;
		newkey->expanded_key_len = 208;
		newkey->num_rounds = 11;
	}
	else
	{
		newkey->key_len = 32;
		newkey->expanded_key_len = 240;
		newkey->num_rounds = 13;
	}
	newkey->expanded_key = ffmem_alloc_arr(uint8_t, newkey->expanded_key_len);
	memcpy(newkey->expanded_key, key, newkey->key_len);
	int num_rounds = (newkey->expanded_key_len/16)*4;
	int rounds_per_cycle = newkey->key_len/4;
	int round;
	for(round=rounds_per_cycle;round<num_rounds;round++)
	{
		if(round%rounds_per_cycle == 0)
		{
			ffaes_rotword(newkey->expanded_key + (round-1)*4, newkey->expanded_key + round*4);
			ffaes_subword(newkey->expanded_key + round*4, newkey->expanded_key + round*4);
			ffaes_xor_rcon(newkey->expanded_key + round*4, newkey->expanded_key + round*4, round/rounds_per_cycle-1);
			ffaes_xor_word((uint32_t*)newkey->expanded_key + (round-rounds_per_cycle), (uint32_t*)newkey->expanded_key + round, (uint32_t*)newkey->expanded_key + round);
		}
		else if(rounds_per_cycle == 8 && round%rounds_per_cycle == 4)
		{
			ffaes_subword(newkey->expanded_key + (round-1)*4, newkey->expanded_key + round*4);
			ffaes_xor_word((uint32_t*)newkey->expanded_key + round, (uint32_t*)newkey->expanded_key + (round-rounds_per_cycle), (uint32_t*)newkey->expanded_key + round);
		}
		else
			ffaes_xor_word((uint32_t*)newkey->expanded_key + (round-1), (uint32_t*)newkey->expanded_key + (round-rounds_per_cycle), (uint32_t*)newkey->expanded_key + round);
	}

	//make a copy of expanded key and apply inverse mix column on all rounds except first and last used for decryption
	newkey->expanded_key_dec = ffmem_alloc_arr(uint8_t, newkey->expanded_key_len-32);
	memcpy(newkey->expanded_key_dec, newkey->expanded_key+16, newkey->expanded_key_len-32);
	uint8_t* p = newkey->expanded_key_dec+newkey->expanded_key_len-32;
	do
	{
		p-=16;
		ffaes_mix_column_inv(p);
	}
	while(p!=newkey->expanded_key_dec);

	return newkey;
}

void ffaes_destroy(ffaes_t* key)
{
	ffmem_free_arr(((ffaes_t*)key)->expanded_key);
	ffmem_free_arr(((ffaes_t*)key)->expanded_key_dec);
	ffmem_free((ffaes_t*)key);
}

void ffaes_encrypt_block(ffaes_t* key, void* cipher_output, void* plaintext_input)
{
	uint32_t state[4];
	uint32_t temp[4];
	int round;
	int ek_index;

	//add round key
	ek_index = 0;
	state[0] = ((uint32_t*)plaintext_input)[0]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[1] = ((uint32_t*)plaintext_input)[1]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[2] = ((uint32_t*)plaintext_input)[2]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[3] = ((uint32_t*)plaintext_input)[3]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];

	//exec rounds except the last round
	for(round=0;round<((ffaes_t*)key)->num_rounds;round++)
	{
		//bytesub, shiftrow, and mixcolumn done in table lookups
		temp[0]= enc0[((uint8_t*)state)[0]]^
					enc1[((uint8_t*)state)[5]]^
					enc2[((uint8_t*)state)[10]]^
					enc3[((uint8_t*)state)[15]];
		temp[1]= enc0[((uint8_t*)state)[4]]^
					enc1[((uint8_t*)state)[9]]^
					enc2[((uint8_t*)state)[14]]^
					enc3[((uint8_t*)state)[3]];
		temp[2]= enc0[((uint8_t*)state)[8]]^
					enc1[((uint8_t*)state)[13]]^
					enc2[((uint8_t*)state)[2]]^
					enc3[((uint8_t*)state)[7]];
		temp[3]= enc0[((uint8_t*)state)[12]]^
					enc1[((uint8_t*)state)[1]]^
					enc2[((uint8_t*)state)[6]]^
					enc3[((uint8_t*)state)[11]];

		//add round key
		state[0] = temp[0]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
		state[1] = temp[1]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
		state[2] = temp[2]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
		state[3] = temp[3]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	}

	//last round without mixcolumn
	ffaes_shiftrow_bytesub((uint8_t*)state);
	state[0] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[1] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[2] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index++];
	state[3] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[ek_index];

	//output
	((uint32_t*)cipher_output)[0] = state[0];
	((uint32_t*)cipher_output)[1] = state[1];
	((uint32_t*)cipher_output)[2] = state[2];
	((uint32_t*)cipher_output)[3] = state[3];
}

void ffaes_decrypt_block(ffaes_t* key, void* plaintext_output, void* cipher_input)
{
	uint32_t state[4];
	uint32_t temp[4];
	int round;
	int ek_index;

	//add round key
	ek_index = ((ffaes_t*)key)->expanded_key_len >> 2;
	state[3] = ((uint32_t*)cipher_input)[3]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[--ek_index];
	state[2] = ((uint32_t*)cipher_input)[2]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[--ek_index];
	state[1] = ((uint32_t*)cipher_input)[1]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[--ek_index];
	state[0] = ((uint32_t*)cipher_input)[0]^((uint32_t*)(((ffaes_t*)key)->expanded_key))[--ek_index];
	ek_index = (((ffaes_t*)key)->expanded_key_len-32) >> 2;

	//exec all other rounds
	for(round=0;round<((ffaes_t*)key)->num_rounds;round++)
	{
		//mixcolumn, bytesub, shiftrow done in table lookups
		temp[0]= dec0[((uint8_t*)state)[0]]^
					dec1[((uint8_t*)state)[13]]^
					dec2[((uint8_t*)state)[10]]^
					dec3[((uint8_t*)state)[7]];
		temp[1]= dec0[((uint8_t*)state)[4]]^
					dec1[((uint8_t*)state)[1]]^
					dec2[((uint8_t*)state)[14]]^
					dec3[((uint8_t*)state)[11]];
		temp[2]= dec0[((uint8_t*)state)[8]]^
					dec1[((uint8_t*)state)[5]]^
					dec2[((uint8_t*)state)[2]]^
					dec3[((uint8_t*)state)[15]];
		temp[3]= dec0[((uint8_t*)state)[12]]^
					dec1[((uint8_t*)state)[9]]^
					dec2[((uint8_t*)state)[6]]^
					dec3[((uint8_t*)state)[3]];

		//add round key
		state[3] = temp[3]^((uint32_t*)(((ffaes_t*)key)->expanded_key_dec))[--ek_index];
		state[2] = temp[2]^((uint32_t*)(((ffaes_t*)key)->expanded_key_dec))[--ek_index];
		state[1] = temp[1]^((uint32_t*)(((ffaes_t*)key)->expanded_key_dec))[--ek_index];
		state[0] = temp[0]^((uint32_t*)(((ffaes_t*)key)->expanded_key_dec))[--ek_index];
	}

	//exec last add round
	ffaes_shiftrow_bytesub_inverse((uint8_t*)state);
	state[3] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[3];
	state[2] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[2];
	state[1] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[1];
	state[0] ^= ((uint32_t*)(((ffaes_t*)key)->expanded_key))[0];

	//output
	((uint32_t*)plaintext_output)[0] = state[0];
	((uint32_t*)plaintext_output)[1] = state[1];
	((uint32_t*)plaintext_output)[2] = state[2];
	((uint32_t*)plaintext_output)[3] = state[3];
}

//Encrypts size_bytes from plaintext_input to cipher_output in ECB mode. Must be multiple of 16.
void ffaes_encrypt(ffaes_t* aes, ffaes_t* key, void* cipher_output, void* plaintext_input, int size_bytes)
{
	if(aes == NULL || key == NULL || cipher_output == NULL || plaintext_input == NULL)
	{
		fflog_debug_print("invalid argument(s)");
		return;
	}
	if(size_bytes <= 0 || size_bytes%16 != 0)
	{
		fflog_debug_print("size_bytes must be greater than 0 and a multiple of 16");
		return;
	}
	int i;
	for(i=0;i<size_bytes;i+=16)
			ffaes_encrypt_block(key, ((uint8_t*)cipher_output)+i, ((uint8_t*)plaintext_input)+i);
}

//Decrypts size_bytes from cipher_input to plaintext_output in ECB mode. Must be multiple of 16.
void ffaes_decrypt(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes)
{
	if(key == NULL || cipher_input == NULL || plaintext_output == NULL)
	{
		fflog_debug_print("invalid argument(s)");
		return;
	}
	if(size_bytes <= 0 || size_bytes%16 != 0)
	{
		fflog_debug_print("size_bytes must be greater than 0 and must be a multiple of 16");
		return;
	}
	int i;
	for(i=0;i<size_bytes;i+=16)
		ffaes_decrypt_block(key, ((uint8_t*)plaintext_output)+i, ((uint8_t*)cipher_input)+i);
}

//Encrypts size_bytes from plaintext_input to cipher_output in ECB mode. Must be multiple of 16.
void ffaes_encrypt_cbc(ffaes_t* key, void* cipher_output, void* plaintext_input, int size_bytes, const void* iv)
{
	if(key == NULL || cipher_output == NULL || plaintext_input == NULL || iv == NULL)
	{
		fflog_debug_print("invalid argument(s)");
		return;
	}
	if(size_bytes <= 0 || size_bytes%16 != 0)
	{
		fflog_debug_print("size_bytes must be greater than 0 and a multiple of 16");
		return;
	}

	//xor the initial vector to the first block of plaintext and encrypt it
	uint32_t* cipher_index = (uint32_t*)cipher_output;
	uint32_t* plaintext_index = (uint32_t*)plaintext_input;
	*cipher_index = *(plaintext_index++) ^ *((uint32_t*)iv);
	*(cipher_index+1) = *(plaintext_index++) ^ *(((uint32_t*)iv)+1);
	*(cipher_index+2) = *(plaintext_index++) ^ *(((uint32_t*)iv)+2);
	*(cipher_index+3) = *(plaintext_index++) ^ *(((uint32_t*)iv)+3);
	ffaes_encrypt_block(key, cipher_index, cipher_index);

	//perform the cipher-block chain to subsequent blocks
	cipher_index += 4;
	uint32_t* end_index = (uint32_t*)(((uint8_t*)cipher_output)+size_bytes);
	while(cipher_index != end_index)
	{
		//xor the ciphertext of the previous block to the current plaintext block then encrypt it
		*cipher_index = *(plaintext_index++) ^ *(cipher_index-4);
		*(cipher_index+1) = *(plaintext_index++) ^ *(cipher_index-3);
		*(cipher_index+2) = *(plaintext_index++) ^ *(cipher_index-2);
		*(cipher_index+3) = *(plaintext_index++) ^ *(cipher_index-1);
		ffaes_encrypt_block(key, cipher_index, cipher_index);
		cipher_index += 4;
	}
}

//Decrypts size_bytes from cipher_input to plaintext_output in ECB mode. Must be multiple of 16.
void ffaes_decrypt_cbc(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes, const void* iv)
{
	if(key == NULL || cipher_input == NULL || plaintext_output == NULL || iv == NULL)
	{
		fflog_debug_print("invalid argument(s)");
		return;
	}
	if(size_bytes == 0 || size_bytes%16 != 0)
	{
		fflog_debug_print("size_bytes must be greater than 0 and a multiple of 16");
		return;
	}

	//decrypt the first cipher block first, then xor the initial vector to get the first plaintext block
	ffaes_decrypt_block(key, plaintext_output, cipher_input);
	*((uint32_t*)plaintext_output) ^= *((uint32_t*)iv);
	*(((uint32_t*)plaintext_output)+1) ^= *(((uint32_t*)iv)+1);
	*(((uint32_t*)plaintext_output)+2) ^= *(((uint32_t*)iv)+2);
	*(((uint32_t*)plaintext_output)+3) ^= *(((uint32_t*)iv)+3);

	//start from the last block and perform cipher-block chain backwards
	uint32_t* cipher_index = (uint32_t*)(((uint8_t*)cipher_input)+size_bytes-16);
	uint32_t* plaintext_index = (uint32_t*)(((uint8_t*)plaintext_output)+size_bytes-16);
	while(plaintext_index != (uint32_t*)plaintext_output)
	{
		ffaes_decrypt_block(key, plaintext_index, cipher_index);
		*(plaintext_index+3) ^= *(--cipher_index);
		*(plaintext_index+2) ^= *(--cipher_index);
		*(plaintext_index+1) ^= *(--cipher_index);
		*plaintext_index ^= *(--cipher_index);
		plaintext_index -= 4;
	}
}

int ffaes_get_cbc_padded_cipher_size(int plaintext_size)
{
	int i = plaintext_size/16;
	if(plaintext_size%16 != 0)
		return (i*16+16)+4;
	return plaintext_size+4;
}

static int ffaes_get_cbc_padded_plaintext_size(void* cipher_input)
{
	ffbit_t* bp = ffbit_create(cipher_input);
	uint32_t size = ffbit_read(bp, 32);
	ffbit_destroy(bp);
	return (int)size;
}

int ffaes_encrypt_cbc_padded(ffaes_t* key, void* cipher_output, void* cipher_input, int size_bytes, const void* iv)
{
	uint32_t cipher_size = (uint32_t)ffaes_get_cbc_padded_cipher_size(size_bytes);
	ffbit_t* bp = ffbit_create(cipher_output);
	ffbit_write(bp, 32, size_bytes);
	uint8_t* p = (uint8_t*)cipher_output+4;
	memcpy(p, cipher_input, size_bytes);
	ffaes_encrypt_cbc(key, p, p, (int)cipher_size-4, iv);
	return cipher_size;
}

int ffaes_decrypt_cbc_padded(ffaes_t* key, void* plaintext_output, void* cipher_input, int size_bytes, const void* iv)
{
	int ret = ffaes_get_cbc_padded_plaintext_size(cipher_input);
	ffaes_decrypt_cbc(key, plaintext_output, (uint8_t*)cipher_input+4, size_bytes-4, iv);
	return ret;
}
