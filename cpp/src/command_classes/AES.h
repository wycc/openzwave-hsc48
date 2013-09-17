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
//      OpenZWave is distributed in the hope that it will be useful,
//      but WITHOUT ANY WARRANTY; without even the implied warranty of
//      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//      GNU Lesser General Public License for more details.
//
//      You should have received a copy of the GNU Lesser General Public License
//      along with OpenZWave.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

#ifndef _AES_H
#define _AES_H
typedef unsigned char BYTE;
void AES128_Encrypt(uint8 *in, uint8 *out, uint8 *key);
void AES_OFB(uint8 *encKey,uint8 *bufdata, int bufdataLength,uint8 *iv);
void AES_CBCMAC( BYTE *iv, BYTE *bufdata, BYTE bufdataLength, BYTE *MAC, BYTE *Auth_Key);
#endif // _AES_H
