/*
 * Security.h
 */

#ifndef SECURITY_H_
#define SECURITY_H_

#include "CommandClass.h"
#include "Mutex.h"
#include "AES.h"


namespace OpenZWave
{
	class ValueBool;
	class Msg;
        
	/** \brief Implements COMMAND_CLASS_SECURITY (0x98), a Z-Wave device command class.
	 */
	class Security: public CommandClass
	{
	public:           
            
		static CommandClass* Create( uint32 const _homeId, uint8 const _nodeId ){ return new Security( _homeId, _nodeId ); }
		virtual ~Security() {}

		 static uint8 const StaticGetCommandClassId(){ return 0x98; }
		 static string const StaticGetCommandClassName(){ return "COMMAND_CLASS_SECURITY"; }

		// From CommandClass
	        virtual uint8 const GetCommandClassId()const{ return StaticGetCommandClassId(); }
		virtual string const GetCommandClassName()const{ return StaticGetCommandClassName(); }
		virtual bool RequestState ( uint32 const _requestFlags, uint8 const _instance, Driver::MsgQueue const _queue );
		virtual bool GetScheme (uint32 const _requestFlags, uint8 const _dummy1, uint8 const _instance, Driver::MsgQueue const _queue);
		virtual bool HandleMsg( uint8 const* _data, uint32 const _length, uint32 const _instance );      
               // virtual bool SupportedGet(Driver::MsgQueue const _queue);          
                
		virtual bool EncryptMessage ( uint8 const* _nonce );
		virtual bool DecryptMessage ( uint8 const* _data, uint32 const _length );
		virtual void SendMsg ( Msg* _msg );
                
                 struct SecurityPayload {uint32 m_length; uint32 m_part; uint8 * m_data; } payload, payload1, payload2;
		virtual void QueuePayload ( SecurityPayload const& _payload );                
		virtual void RequestNonce ();
		virtual void SendNonceReport ();

	protected:
		virtual void GenerateAuthentication (uint8 const* _data, uint32 const _length, uint8 const _sendingNode, uint8 const _receivingNode, char* _authentication, char const * m_initializationVector);
		virtual bool GetSenderNonce(int id){return senderNonce;} ;
		virtual void GenerateNonce( uint8* _nonce);

	private:
		Security( uint32 const _homeId, uint8 const _nodeId ): CommandClass( _homeId, _nodeId ){}
                
		uint8 Network_Key[16];
		uint8 Encrypt_Key[16];
		uint8 Auth_Key[16];
                
		uint32 m_w,m_z;
                
		uint8 senderNonce[8];
		uint32 nonceExpiredTime;		// We should clean the publicNonceId and publicNonce when this time is expired.
                Mutex* m_queueMutex;            
                std::vector <SecurityPayload> m_queue;
	};
	
	
}

#endif /* SECURITY_H_ */
