/*
cdecode.h - c header for a base64 decoding algorithm
This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

#ifndef _INCL_BASE64_H_
#define _INCL_BASE64_H_

#include <stdint.h>

typedef enum
{
	step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
	base64_decodestep step;
	char plainchar;
} base64_decodestate;

void base64_init_decodestate(base64_decodestate* state_in);
int base64_decode_value(char value_in);
int base64_decode_block(const char* code_in, const int length_in, uint8_t* plaintext_out, base64_decodestate* state_in);


typedef enum
{
	step_A, step_B, step_C
} base64_encodestep;

typedef struct
{
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;

void base64_init_encodestate(base64_encodestate* state_in);
char base64_encode_value(char value_in);
int base64_encode_block(const uint8_t* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in);
int base64_encode_blockend(char* code_out, base64_encodestate* state_in);

#endif

