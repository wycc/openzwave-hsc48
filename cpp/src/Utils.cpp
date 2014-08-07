//-----------------------------------------------------------------------------
//
//	Utils.h
//
//	Miscellaneous helper functions
//
//	Copyright (c) 2010 Mal Lansell <openzwave@lansell.org>
//
//	SOFTWARE NOTICE AND LICENSE
//
//	This file is part of OpenZWave.
//
//	OpenZWave is free software: you can redistribute it and/or modify
//	it under the terms of the GNU Lesser General Public License as published
//	by the Free Software Foundation, either version 3 of the License,
//	or (at your option) any later version.
//
//	OpenZWave is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//	GNU Lesser General Public License for more details.
//
//	You should have received a copy of the GNU Lesser General Public License
//	along with OpenZWave.  If not, see <http://www.gnu.org/licenses/>.
//
//-----------------------------------------------------------------------------

#include "Defs.h"
#include "Utils.h"
#include <sys/socket.h>
#include <netinet/in.h>
using namespace OpenZWave;
template class list<string>;

//-----------------------------------------------------------------------------
// <OpenZWave::ToUpper>
// Convert a string to all upper-case.
//-----------------------------------------------------------------------------
string OpenZWave::ToUpper
( 
	string const& _str
) 
{
	string upper = _str;
	transform( upper.begin(), upper.end(), upper.begin(), ::toupper ); 
	return upper;
}

//-----------------------------------------------------------------------------
// <OpenZWave::ToLower>
// Convert a string to all lower-case.
//-----------------------------------------------------------------------------
string OpenZWave::ToLower
( 
	string const& _str
) 
{
	string lower = _str;
	transform( lower.begin(), lower.end(), lower.begin(), ::tolower ); 
	return lower;
}

void webdebug_add(unsigned char type, unsigned char subtype, unsigned char a1, unsigned char a2, unsigned char a3, unsigned char a4)
{
	Webdebug wd;
	struct sockaddr_in addr;
	static int fd=-1;

	if (fd == -1)
		fd=socket(AF_INET, SOCK_DGRAM,0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(1102);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	wd.type = type;
	wd.subtype = subtype;
	wd.a1 = a1;
	wd.a2 = a2;
	wd.a3 = a3;
	wd.a4 = a4;
	sendto(fd,&wd, sizeof(wd),0,(struct sockaddr *)&addr,sizeof(addr));
}
