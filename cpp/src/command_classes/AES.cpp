//-----------------------------------------------------------------------------
//
//      AES.h
//
//      Implementation of 128-bit AES Encryption
//
//      Copyright (c) 2010 Mal Lansell <openzwave@lansell.org>
//
//      SOFTWARE NOTICE AND LICENSE
//
//      This file is part of OpenZWave.
//
//      OpenZWave is free software: you can redistribute it and/or modify
//      it under the terms of the GNU Lesser General Public License as published
//      by the Free Software Foundation, either version 3 of the License,
//      or (at your option) any later version.
//
//      OpenZWave is distributed _in the hope that it will be useful,
//      but WITHOUT ANY WARRANTY; without even the implied warranty of
//      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//      GNU Lesser General Public License for more details.
//
//      You should have received a copy of the GNU Lesser General Public License
//      along with OpenZWave.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

#include <string.h>

#include "libaes/aes.h"
#include <stdio.h>
typedef unsigned char uint8;
typedef uint8 BYTE;
uint8 plaintext16ByteChunk[16];

void AES128_Encrypt(uint8 *in, uint8 *out, uint8 *key)
{
    aes_ctx aes_ctx;
    uint8 buf[16];
    memset(&aes_ctx, 0, sizeof(aes_ctx));

    //aes_set_blk(&aes_ctx, 128);
    aes_set_key(&aes_ctx, key, 16,aes_both);
    aes_encrypt(&aes_ctx, in, buf);
    memcpy(out,buf,16);
}

void AES_OFB(uint8 *encKey,uint8 *bufdata, int bufdataLength,uint8 *iv)
{
  BYTE i, j;
  BYTE ivIndex;
  int blockIndex = 0;
  int cipherIndex=0;

  memset((BYTE *)plaintext16ByteChunk, 0, 16);
  for (cipherIndex = 0; cipherIndex < bufdataLength; cipherIndex++)
  {
    plaintext16ByteChunk[blockIndex] = *(bufdata + cipherIndex);
    blockIndex++;
    if (blockIndex == 16)
    {
      AES128_Encrypt(iv, iv,encKey);
      ivIndex = 0;
      for (i = (cipherIndex - 15); i <= cipherIndex; i++)
      {
        //  TO#03067 AES_OFB method fails with payload of 32bytes.
////        bufdata[i] = (BYTE)(plaintext16ByteChunk[i] ^ authData.iv[ivIndex]);
        bufdata[i] = (BYTE)(plaintext16ByteChunk[ivIndex] ^ iv[ivIndex]);
        ivIndex++;
      }
      memset((BYTE *)plaintext16ByteChunk, 0, 16);
      blockIndex = 0;
    }
  }

  if (blockIndex != 0)
  {
    AES128_Encrypt(iv, iv,encKey);
    ivIndex = 0;
    for (j = 0; j < blockIndex; j++)
    {
      bufdata[cipherIndex - blockIndex + j] = (BYTE)(plaintext16ByteChunk[j] ^ iv[j]);
      ivIndex++;
    }
  }
}


void
AES_CBCMAC(
  BYTE *iv,
  BYTE *bufdata,
  BYTE bufdataLength,
  BYTE *MAC, BYTE *Auth_Key)
{
  register BYTE i, j, k;
  BYTE inputData[512];
  BYTE blockIndex,cipherIndex;

  // Generate input: [header] . [data]
  memcpy((BYTE *)&inputData[0], (BYTE *) iv, 20);
  memcpy((BYTE *)&inputData[20], bufdata, bufdataLength);
  // Perform initial hashing

  // Build initial input data, pad with 0 if length shorter than 16
  for (i = 0; i < 16; i++)
  {
    if (i >= 20 + bufdataLength)
    {
      plaintext16ByteChunk[i] = 0;
    }
    else
    {
      plaintext16ByteChunk[i] = inputData[i];
    }

  }
  AES128_Encrypt(&plaintext16ByteChunk[0], MAC,Auth_Key);
  memset((BYTE *)plaintext16ByteChunk, 0, 16);

  blockIndex = 0;
  // XOR tempMAC with any left over data and encrypt

  for (cipherIndex = 16; cipherIndex < (20 + bufdataLength); cipherIndex++)
  {
    plaintext16ByteChunk[blockIndex] = inputData[cipherIndex];
    blockIndex++;
    if (blockIndex == 16)
    {
      for (j = 0; j <= 15; j++)
      {
        MAC[j] = (BYTE)(plaintext16ByteChunk[j] ^ MAC[j]);
      }
      memset((BYTE *)plaintext16ByteChunk, 0, 16);
      blockIndex = 0;

      AES128_Encrypt(MAC, MAC,Auth_Key);
    }
  }

  if (blockIndex != 0)
  {
    for (k = 0; k < 16; k++)
    {
      MAC[k] = (BYTE)(plaintext16ByteChunk[k] ^ MAC[k]);
    }
    AES128_Encrypt(MAC, MAC,Auth_Key);
  }
}



#ifdef TEST
uint8 senderNonce1[8] = {0xDE,0x90,0x75,0x62,0xCC,0xC7,0xD1,0x77};
uint8 receiverNonce1[8] = {0xE5,0x05,0xA0,0x60,0x2F,0xC1,0xC5,0x19};
uint8 payload1[16] = {0xFC,0x43,0x1D,0xE5};
uint8 MAC1[8] = {0xC4,0xDB,0xE5,0x4B,0x2E,0x5A,0x74,0xEF};
uint8 senderNonce2[8] = {0x4D,0xBF,0x05,0x5F,0x82,0x0E,0x87,0xE6};
uint8 receiverNonce2[8] = {0xE1,0xF8,0x66,0x65,0xD0,0xFD,0xAA,0x05};
uint8 payload2[16] = {0x33,0xD5,0x86,0x86};
uint8 MAC2[8] = {0xC5,0x17,0x3B,0x44,0x41,0x05,0x4B,0x7F};

uint8 senderNonce[8] = {0x11,0xB2,0x10,0x09,0xB6,0x45,0xC6,0xE9};
uint8 receiverNonce[8] = {0x92,0x45,0xD2,0x1E,0x73,0xCA,0xCF,0x8A};
uint8 payload[] = {0xA5,0xD3,0xC5,0xAB,0x54,0x89,0xD2,0x38,0xD6,0x8D,0x24,0x62,0x4C,0xAE,0x30,0xD4,0x1B,0x3D,0x09};
uint8 cleartext[] = {0xC7,0x05,0xEA,0x8C,0x15,0x0B,0x58,0xB7,0xBC,0xC5,0xE1,0xA0,0x98,0x38,0xA0,0x0B};
uint8 MAC[8] = {0x32,0xD0,0x23,0x51,0x10,0xC4,0xF8,0x95};
main()
{
	AES aes;
	uint8 V1[16];
	uint8 V2[16];
	uint8 tmp_key[16];
	uint8 Network_Key[16];
	uint8 Encrypt_Key[16];
	uint8 Auth_Key[16];
	uint8 iv[16];
	uint8 result[32];
	uint8 buffer[512];
	int i;
	
	memset(Network_Key, 0x00, 16);
	memset(V2,0x55,16);
	memset(V1,0xAA,16);                                   

	memcpy(result,payload,sizeof(payload));

	for(int i=0;i<8;i++) {
		iv[i] = senderNonce[i];
		iv[i+8] = receiverNonce[i];
	}
	AES128_Encrypt(V1, Encrypt_Key,Network_Key);
	AES128_Encrypt(V2, Auth_Key,Network_Key);
	printf("Key = ");
	for(int i=0;i<16;i++) {
		printf("%02X ", Encrypt_Key[i]);
	}
	printf("\n");
	AES_OFB1(Encrypt_Key,(uint8 *)result,sizeof(payload),(uint8 *)iv);
	for(int i=0;i<sizeof(payload);i++) {
		printf("%02X ", result[i]);
	}
	printf("\n");
	printf("cleartext:\n");
	for(i=0;i<sizeof(cleartext);i++) {
		printf("%02X ",cleartext[i]);
	}
	printf("\n");

	
	for(i=0;i<8;i++) {
		iv[i] = senderNonce[i];
		iv[i+8] = receiverNonce[i];
	}
 	for(i=0;i<16;i++)
	{
       		buffer[i] = iv[i];
	}
        buffer[16] = 0x81;
        buffer[17] = 1;
        buffer[18] = 5;
        buffer[19] = sizeof(payload);

	AES_CBCMAC(buffer,payload,sizeof(payload),result,Auth_Key);
	printf("result:\t");
	for(i=0;i<8;i++) {
		printf("%02X ", result[i]);
	}
	printf("\n");
	printf("MAC:\t");
	for(i=0;i<8;i++) {
		printf("%02X ", MAC[i]);
	}
	printf("\n");
}
#endif
