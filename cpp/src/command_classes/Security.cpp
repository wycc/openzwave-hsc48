// vim: ts=8 sw=8
//-----------------------------------------------------------------------------
//
//      Security.cpp
//
//      Implementation of the Z-Wave COMMAND_CLASS_Security
//
//      Copyright (c) 2011 Mal Lansell <openzwave@lansell.org>
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
#include "Node.h"
#include "Security.h"
#include "CommandClasses.h"
#include "Association.h"
#include "Defs.h"
#include "AES.h"
#include "Msg.h"
#include "Driver.h"
#include "Notification.h"
#include "Log.h"
#include "ValueByte.h"
#include "Mutex.h"
#include <sys/time.h>

using namespace OpenZWave;

enum SecurityCmd
{
        SecurityCmd_SupportedGet                        = 0x02,
        SecurityCmd_SupportedReport                     = 0x03,
        SecurityCmd_SchemeGet                           = 0x04,
        SecurityCmd_SchemeReport                        = 0x05,
        SecurityCmd_NetworkKeySet                       = 0x06,
        SecurityCmd_NetworkKeyVerify                    = 0x07,
        SecurityCmd_SchemeInherit                       = 0x08,
        SecurityCmd_NonceGet                            = 0x40,
        SecurityCmd_NonceReport                         = 0x80,
        SecurityCmd_MessageEncap                        = 0x81,
        SecurityCmd_MessageEncapNonceGet                = 0xc1
};

enum
{
        SecurityScheme_Zero  = 0x00

};

        

//-----------------------------------------------------------------------------
// <Security::RequestState>                                                                                                
// Request current state from the device                                                                          
//-----------------------------------------------------------------------------
bool Security::RequestState
(
	uint32 const _requestFlags,
	uint8 const _instance,
	Driver::MsgQueue const _queue
)
{
      
	if( _requestFlags & RequestFlag_Static )
	{
		return GetScheme( _requestFlags, 0, _instance, _queue );
	}

	return false;
}

//-----------------------------------------------------------------------------
// <Security::RequestValue>                                                                                                
// Request current state from the device                                                                          
//-----------------------------------------------------------------------------
bool Security::GetScheme (uint32 const _requestFlags, uint8 const _dummy1, uint8 const _instance, Driver::MsgQueue const _queue)

{
 
	  Msg * msg = new Msg( "Negotiating Security Scheme", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
		msg->Append( GetNodeId() );
		msg->Append( 3 );
		msg->Append( GetCommandClassId() );
		msg->Append( SecurityCmd_SchemeGet );
                msg->Append( SecurityScheme_Zero );               
		msg->Append( GetDriver()->GetTransmitOptions() );
		GetDriver()->SendMsg( msg, _queue );
		return true;

}

//-----------------------------------------------------------------------------
// <Security::HandleMsg>
// Handle a message from the Z-Wave network
//-----------------------------------------------------------------------------
bool Security::HandleMsg
(
        uint8 const* _data,
        uint32 const _length,
        uint32 const _instance  // = 1
)
{
        switch( (SecurityCmd)_data[0] )
        {
            
               case SecurityCmd_SchemeReport:
                {
                        Log::Write( LogLevel_Info, "Received SecurityCmd_SchemeReport from node %d", GetNodeId());
                        uint8 schemes = _data[1];

                        if( schemes == SecurityScheme_Zero )
                        {
                                // We're good to go.  We now wait for a key to be sent by the device.
                           
                                Log::Write( LogLevel_Info, GetNodeId(), " Security scheme agreed. Key expected from device." );

				uint8 V1[16];
				uint8 V2[16];
				//uint8 tmp_key[16];
				
				memset(Network_Key, 0x00, 16);
				memset(V1,0xAA,16);				    
				memset(V2,0x55,16);                                   
				AES128_Encrypt(V1, Encrypt_Key,Network_Key);
				AES128_Encrypt(V2, Auth_Key,Network_Key);
                                
                                Msg* msg = new Msg( "Network_Key_set", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
				msg->Append( GetNodeId() );
				msg->Append( 18 );
				msg->Append( GetCommandClassId() );
				msg->Append( SecurityCmd_NetworkKeySet);
				for(int i=0;i<16;i++) 
                                {
				     msg->Append( Network_Key[i]);
				}
                                
				msg->Append( GetDriver()->GetTransmitOptions() );
				SendMsg(msg);
                                                                  
                                return true; 
                        }
                        
                        else
                        {
                                // No common security scheme.  The device will
                                // continue as an unsecured node.
                                Log::Write( LogLevel_Info, GetNodeId(), " No common security scheme.  The device will continue as an unsecured node.", schemes );
                               
                                // TBD - turn off security support for this node
                        }
                        break;
                }
               
                case SecurityCmd_NonceGet:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_NonceGet from node %d", GetNodeId() );
                        SendNonceReport();
                        break;
                }
                case SecurityCmd_NonceReport:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_NonceReport from node %d", GetNodeId() );
                        
                        EncryptMessage( &_data[1] ); 
                        
                        break;
                }
                
                case SecurityCmd_SupportedReport:
                {
                        Log::Write( LogLevel_Info, "Received SecurityCmd_SupportedReport from node %d : Security is %s", GetNodeId(), _data[1] ? "SecuritySupported" : "SecurityNotSupported" );
                        break;
                }
             
                case SecurityCmd_NetworkKeySet:
                {
                        Log::Write(LogLevel_Info, GetNodeId(), " Received SecurityCmd_NetworkKeySet from node %d ", GetNodeId() );
                        break;
                }
                
                case SecurityCmd_NetworkKeyVerify:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_NetworkKeyVerify from node %d", GetNodeId() );
                        uint8 V1[16];
		        uint8 V2[16];
                        //uint8 tmp_key[16];
                        
                        //Generating Keys            			   
                        memset(V1,0xAA,16);
                        memset(V2,0x55,16);                                   
			AES128_Encrypt(V1, Encrypt_Key,Network_Key);
			AES128_Encrypt(V2, Auth_Key,Network_Key);
                        break;
                }
                
                case SecurityCmd_SchemeInherit:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_SchemeInherit from node %d", GetNodeId() );
                        break;
                }
               
                case SecurityCmd_MessageEncap:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_MessageEncap from node %d", GetNodeId() );
                        DecryptMessage( _data, _length );
                        break;
                }
                
                case SecurityCmd_MessageEncapNonceGet:
                {
                        Log::Write( LogLevel_Info, GetNodeId(), "Received SecurityCmd_MessageEncapNonceGet from node %d", GetNodeId() );
                        if( DecryptMessage( _data, _length ) )
                        {
                                SendNonceReport();
                        }
                        break;
                }
                
                default:
                {
                        return false;
                }
        }

        return true;
}

/*//-----------------------------------------------------------------------------
// <Security::SupportedGet>
// Request current value from the device
//-----------------------------------------------------------------------------
bool Security::SupportedGet
(
	Driver::MsgQueue const _queue
)

{
	Msg* msg = new Msg( "Supported_Get", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->Append( GetNodeId() );
	msg->Append( 2 );
	msg->Append( GetCommandClassId() );
	msg->Append( EncryptMessage (senderNonce) );
	msg->Append( GetDriver()->GetTransmitOptions() );
	GetDriver()->SendMsg( msg, _queue );
	return true;
}*/

//-----------------------------------------------------------------------------
// <Security::GenerateNonce>
// Generating Nonces
//-----------------------------------------------------------------------------
void Security::GenerateNonce
(
        uint8* _nonce
)
{
    
  	// Use system time as the seed. 10ms guarantee to perform a context switch. The rutrn time should be random.
	struct timeval now,to;

	gettimeofday(&now,NULL);
	m_w = now.tv_usec;
	to.tv_sec = 0;
	to.tv_usec = 10000;
	select(0,NULL,NULL,NULL, &to);
	gettimeofday(&now,NULL);
	m_w = now.tv_usec;
	nonceExpiredTime = now.tv_sec + 10;

	// Use psuedo random number generator to generate the nonce
	int i;
	for(i=0; i<8; i++) 
        {
	   m_z = 36969 * (m_z & 65535) + (m_z >> 16);
	   m_w = 18000 * (m_w & 65535) + (m_w >> 16);
	   _nonce[i] = m_w % 0xff;
	}  
    
}

//-----------------------------------------------------------------------------
// <Security::SendMsg>
// Queue a message to be securely sent by the Z-Wave PC Interface
//-----------------------------------------------------------------------------
void Security::SendMsg
(
        Msg* _msg
)
{
        _msg->Finalize();

        uint8* buffer = _msg->GetBuffer();
        if( _msg->GetLength() < 7 )
        {
                // Message too short
                assert(0);
                return;
        }

        if( buffer[3] != FUNC_ID_ZW_SEND_DATA )
        {
                // Invalid message type
                assert(0);
                return;
        }

        uint8 length = buffer[5];        
        
        if( length > 28 )
        {
                // Message must be split into two parts

                payload.m_length = 28;
                payload.m_part = 1;
                memcpy( payload.m_data, &buffer[6], payload.m_length );
                QueuePayload( payload1 );

                payload.m_length = length-28;
                payload.m_part = 2;
                memcpy( payload.m_data, &buffer[34], payload.m_length );
                QueuePayload( payload2 );
        }

        else
        {
                // The entire message can be encapsulated as one
                payload.m_length = length;
                payload.m_part = 0;                             // Zero means not split into separate messages
                payload.m_data =  new uint8 [(payload.m_length+15)/16*16];
                memcpy( payload.m_data, &buffer[6], payload.m_length );
                QueuePayload( payload );
        }
}

//-----------------------------------------------------------------------------
// <Security::QueuePayload>
// Queue data to be encapsulated by the Security Command Class, on
// receipt of a nonce value from the remote node.
//-----------------------------------------------------------------------------
void Security::QueuePayload
(
    SecurityPayload const& _payload
)

{
       m_queueMutex= new Mutex() ;
       m_queueMutex->Lock();

        m_queue.push_back( _payload );
        
	bool m_waitingForNonce = false ;

        if( !m_waitingForNonce )
        {
                // Request a nonce from the node.  Its arrival
                // will trigger the sending of the first payload
                RequestNonce();
        }

        m_queueMutex->Release();
}

//-----------------------------------------------------------------------------
// <Security::EncryptMessage>
// Encrypt and send a Z-Wave message securely.
//-----------------------------------------------------------------------------
bool Security::EncryptMessage
(
        uint8 const* _nonce
)
{
        
	uint8 i;
	uint8 EP[29];
	uint8 MAC[64];
	uint8 iv[16];

       m_queueMutex= new Mutex() ;

       m_queueMutex->Lock();

        if( m_queue.empty() )
        {
                // Nothing to do
                m_queueMutex->Release();
                return false;
        }
                       
        m_queue.front();
          
        uint32 queueSize = m_queue.size();
        m_queueMutex->Release();

        // Encapsulate the message fragment
        Msg* msg = new Msg( "Security Encapsulated message fragment", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true );
        msg->Append( GetNodeId() );
        msg->Append( payload.m_length +20 );
        msg->Append( GetCommandClassId() );
        msg->Append( (queueSize>1) ? SecurityCmd_MessageEncapNonceGet : SecurityCmd_MessageEncap );
       
	GetSenderNonce(GetNodeId());
        
        
	for(i=0;i<8;i++)
        {
		msg->Append(senderNonce[i]);
        }
              
        // Append the sequence data
        
        uint8 sequence;
        uint8 m_sequenceCounter = 0;
        
        if ( payload.m_part == 0 )
        {
            sequence = 0 ;
        }
        
        else if( payload.m_part == 1 )
        {
            sequence = (++m_sequenceCounter) & 0x0f;
            sequence |= 0x10;
        }
        
        if( payload.m_part == 2 )
        {
            sequence = m_sequenceCounter & 0x0f;
            sequence |= 0x30; 
        }
	msg->Append(sequence);
        
        for(i=0; i<8; i++) 
        {            
	    iv[i] = senderNonce[i];
	    iv[i+8] = _nonce[i];
	}
                  
        //EncryptOFB(payload.m_data, EP);
	memcpy(EP, payload.m_data, payload.m_length);
        AES_OFB(Encrypt_Key, EP,payload.m_length,iv);
        
        //Appending payload
	for(i=0; i<payload.m_length; i++) 
        {
	    msg->Append(EP[i]);
	}

        //Sending Nonce identifier
	msg->Append(_nonce[0]);
               
        //Generate authentication
	GenerateAuthentication(EP, payload.m_length,1, GetNodeId(),(char *)MAC, (char *)iv);
        
        //Sending authentication
	for(i=0; i<8; i++)
        {
	    msg->Append(MAC[i]);
        }
        
        //Sending the whole frame       
        Driver::MsgQueue const _queue = Driver::MsgQueue_Send;
        msg->Append( GetDriver()->GetTransmitOptions() );
        GetDriver()->SendMsg( msg, _queue );

        return true;
}

 //-----------------------------------------------------------------------------
// <Security::GenerateAuthentication>
// Generate authentication data from a security-encrypted message
//-----------------------------------------------------------------------------
void Security::GenerateAuthentication
(
        uint8 const* _data,                             // Starting from the command class command
        uint32 const _length,          
        uint8 const _sendingNode,
        uint8 const _receivingNode,
        char * _authentication,                  // 8-byte buffer that will be filled with the authentication data
        char const * m_initializationVector
)
{
        // Build a buffer containing a 4-byte header and the encrypted
        // message data, padded with zeros to a 16-byte boundary.
        char buffer[256];
        char MAC[16];
  
	for(int i=0;i<16;i++)
	{
     
       		buffer[i] = m_initializationVector[i];
     
	}
        buffer[16] = (m_queue.size()>1) ? SecurityCmd_MessageEncapNonceGet : SecurityCmd_MessageEncap;
        buffer[17] = _sendingNode;
        buffer[18] = _receivingNode;
        buffer[19] = _length;
        
        for (uint8 i=0; i < _length; i++)
        {
           memcpy( &buffer[20+i], &_data[i], _length );    // Encrypted message
        }
        AES_CBCMAC((BYTE *)buffer, (BYTE *)&_data[0],_length,(BYTE*)MAC, (BYTE*)Auth_Key);
        memcpy(_authentication,MAC,8);
}

//-----------------------------------------------------------------------------
// <Security::DecryptMessage>
// Decrypt a security-encapsulated message from the Z-Wave network
//-----------------------------------------------------------------------------
bool Security::DecryptMessage
(
        uint8 const* _data,
        uint32 const _length
)
{
        //Decryption
	uint8 iv[16];
	uint8 EP[32];
	char buf[512];
    
        /*uint8* pPrivateNonce = &_data[1];                               // 8 bytes in length
        bool secondFrame = ((_data[9] & 0x20) != 0);
        bool sequenced = ((_data[9] & 0x10) != 0);
        uint8 sequenceCount = _data[9] & 0x0f;
        uint8 nonceId = _data[_length-10];
        uint8* pAuthentication = &_data[_length-9];  */           // 8 bytes in length

	// copy the sender's nonce to the iv
	memcpy(iv, &_data[1],8);
	// get the internal nonce to the iv
	memcpy(iv+8, senderNonce, 8);
	// We need to verify the MAC here, skip it for now
	memset(buf,0,512);
	memcpy(buf,payload.m_data,payload.m_length);
	AES_OFB(Encrypt_Key, EP, payload.m_length, iv);
	memset(buf,0,512);
	for(int i; i< 16;i++)
		snprintf(buf+i*3,512, "%02x ",EP[i]);
	Log::Write(LogLevel_Info,"Decrypt to %s", buf);

        return true;
}


//-----------------------------------------------------------------------------
// <Security::RequestNonce>
// Request a nonce from the node
//-----------------------------------------------------------------------------
void Security::RequestNonce
(
)
{
      
        Driver::MsgQueue const _queue = Driver::MsgQueue_Send;
        Msg* msg = new Msg( "SecurityCmd_NonceGet", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
        msg->Append( GetNodeId() );
        msg->Append( 2 );
        msg->Append( GetCommandClassId() );
        msg->Append( SecurityCmd_NonceGet );
        msg->Append( TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_AUTO_ROUTE );
        GetDriver()->SendMsg( msg, _queue  );
        

        // Reset the nonce timer.  The nonce report
        // must be received within 10 seconds.
 
       // WaitingTenSec();
}


//-----------------------------------------------------------------------------
// <Security::SendNonceReport>
// Send a nonce to the node
//-----------------------------------------------------------------------------
void Security::SendNonceReport ()
{
	
        Driver::MsgQueue const _queue = Driver::MsgQueue_Send;

	GenerateNonce(senderNonce);

        Msg* msg = new Msg( "SecurityCmd_NonceReport", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
        msg->Append( GetNodeId() );
        msg->Append( 10 );
        msg->Append( GetCommandClassId() );
        msg->Append( SecurityCmd_NonceReport );

	//uint8 nonce[8];
	//GetSenderNonce(GetNodeId(), nonce);
        for( int i=0; i<8; ++i )
        {
                msg->Append( senderNonce[i] );
        }
        msg->Append( TRANSMIT_OPTION_ACK | TRANSMIT_OPTION_AUTO_ROUTE );
        GetDriver()->SendMsg( msg, _queue );

        // The nonce must be expired after 10 seconds. This check will be performed when the next encrypted packet arrived.
}

