#include "CommandClasses.h"
#include "Security.h"
#include "Defs.h"
#include "Msg.h"
#include "Driver.h"
#include "Node.h"
#include "Log.h"

#include "ValueString.h"

using namespace OpenZWave;

enum VersionCmd
{
	SecurityCmd_Network_Key_set			= 0x06,
	SecurityCmd_Network_Key_Verify      = 0x07,
	SecurityCmd_Command_Supported_Get   = 0x02,
	SecurityCmd_Command_Supported_Report= 0x03,
	SecurityCmd_Message_Encapsulation   = 0x81,
	SecurityCmd_Message_Encapsulation_Nonce_Get = 0xC1,
	SecurityCmd_Nonce_Get               = 0x40,
	SecurityCmd_Nonce_Report            = 0x40,
	SecurityCmd_Scheme_Get              = 0x04,
	SecurityCmd_Sheme_Report            = 0x05,
	SecurityCmd_Sheme_Inherit           = 0x08,

};


//-----------------------------------------------------------------------------
// <Security::Security>
// Constructor
//-----------------------------------------------------------------------------
Security::Security
(
	uint32 const _homeId,
	uint8 const _nodeId
):
	CommandClass( _homeId, _nodeId ),
	m_classGetSupported( true )
{
	LoadKey();
}

//-----------------------------------------------------------------------------
// <Security::LoadKey>
// Load network key
//-----------------------------------------------------------------------------
void Security::LoadKey
( 
)
{
}

//-----------------------------------------------------------------------------
// <Security::ReadXML>
// Read configuration.
//-----------------------------------------------------------------------------
void Security::ReadXML
( 
	TiXmlElement const* _ccElement
)
{
	CommandClass::ReadXML( _ccElement );

}

//-----------------------------------------------------------------------------
// <Security::WriteXML>
// Save changed configuration
//-----------------------------------------------------------------------------
void Security::WriteXML
( 
	TiXmlElement* _ccElement
)
{
	CommandClass::WriteXML( _ccElement );
}

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
	if( ( _requestFlags & RequestFlag_Static ) && HasStaticRequest( StaticRequest_Values ) )
	{
		return RequestValue( _requestFlags, 0, _instance, _queue );
	}

	return false;
}

//-----------------------------------------------------------------------------
// <Security::RequestValue>
// Request current value from the device
//-----------------------------------------------------------------------------
bool Security::RequestValue
(
	uint32 const _requestFlags,
	uint8 const _dummy1,		// = 0
	uint8 const _instance,
	Driver::MsgQueue const _queue
)
{
	if( _instance != 1 )
	{
		// This command class doesn't work with multiple instances
		return false;
	}

	return true;
}

//-----------------------------------------------------------------------------
// <Security::SavedNounce>
// Save the Nounce
//-----------------------------------------------------------------------------
void Security::SaveNounce(char *data)
{
	memcpy(m_nounce,data,16);
}

//-----------------------------------------------------------------------------
// <Security::SavedNetworkKey>
// Save the network key from another controller
//-----------------------------------------------------------------------------
void Security::SaveNetworkKey(char *data)
{
	memcpy(m_key,data,16);
}


//-----------------------------------------------------------------------------
// <Security::NetworkKeySet>
// Send the key to the other side
//-----------------------------------------------------------------------------
void Security::NetworkKeySet()
{
	if( _instance != 1 )
	{
		// This command class doesn't work with multiple instances
		return false;
	}
	Msg* msg = new Msg( "SecurityCmd_NetworkKeySet", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->Append( GetNodeId() );
	msg->Append( 2+16 );
	msg->Append( GetCommandClassId() );
	msg->Append( SecurityCmd_Get );
	for(int i=0;i<16;i++)
		Msg->Append(m_networkkey[i]);
	msg->Append( GetDriver()->GetTransmitOptions() );
	GetDriver()->SendMsg( msg, _queue );
	return true;
}

bool Security::HandleMsg
//-----------------------------------------------------------------------------
// <Security::HandleMsg>
// Handle a message from the Z-Wave network
//-----------------------------------------------------------------------------
bool Security::HandleMsg
(
	uint8 const* _data,
	uint32 const _length,
	uint32 const _instance	// = 1
)
{
	if( Node* node = GetNodeUnsafe() )
	{
		if( SecurityCmd_Sheme_Report == (SecurityCmd)_data[0] )
		{
			stopTimer();
			NetworkKeySet();
			node->enableSecurity();
		} else if (SecurityCmd_Nonce_Report == (SecurityCmd)_data[0]) {
			SaveNounce(&_data[1]);
		} else if (SecurityCmd_Scheme_Get == (SecurityCmd)_data[0]) {
			if (_data[1] != SECURITY_SCHEME_0) {
				// We can not support this scheme, ignore it and the controller will timeout eventually
				return;
			}
		} else {
			Decrypted(_data);
			if( Node* node = GetNodeUnsafe() )
			{
				if( Security::GetStaticCommandClassId() == (SecurityCmd)_data[0] ) {
					HandleEncryptedMsg(_data,_length,_instance);
				} else {
					// Dispatch to other command class
				}
			}
		}
	}

	return false;
}

//-----------------------------------------------------------------------------
// <Security::InheritSecurityScheme>
// 
//-----------------------------------------------------------------------------
bool Security::InheritSecurityScheme()
{
	StopTimer();
	StartTimer();
	Msg* msg = new Msg( "SecurityCmd_Scheme_Inherit", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->Append( GetNodeId() );
	msg->Append( 3 );
	msg->Append( GetCommandClassId() );
	msg->Append( SecurityCmd_Scheme_Inherit );
	msg->Append( SECURITY_SCHEME_0 );
	msg->Append( GetDriver()->GetTransmitOptions() );
	Encrypt(msg);
	GetDriver()->SendMsg( msg, _queue );
}
//-----------------------------------------------------------------------------
// <Security::SendInheritReport>
// 
//-----------------------------------------------------------------------------
bool Security::SendInheritReport(uint8 const *_data)
{
	StopTimer();
	Msg* msg = new Msg( "SecurityCmd_Scheme_Report", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->Append( GetNodeId() );
	msg->Append( 3 );
	msg->Append( GetCommandClassId() );
	msg->Append( SecurityCmd_Scheme_Report );
	msg->Append( SECURITY_SCHEME_0 );
	msg->Append( GetDriver()->GetTransmitOptions() );
	Encrypt(msg);
	GetDriver()->SendMsg( msg, _queue );
}

//-----------------------------------------------------------------------------
// <Security::SendCommandSupported>
//  Send report for the supported security command class. For the OZW, we should the controller replication only.
//-----------------------------------------------------------------------------
bool Security::SendCommandSupported(uint8 const *_data)
{
	StopTimer();
	Msg* msg = new Msg( "SecurityCmd_Command_Supported", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true, true, FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->Append( GetNodeId() );
	msg->Append( 2 + 1 );
	msg->Append( GetCommandClassId() );
	msg->Append( SecurityCmd_Command_Supported_Report );
	msg->Append( ControllerReplication::GetStaticCommandClassId());
	msg->Append( GetDriver()->GetTransmitOptions() );
	Encrypt(msg);
	GetDriver()->SendMsg( msg, _queue );
}


//-----------------------------------------------------------------------------
// <Security::HandleEncryptedMsg>
// Handle a message from the Z-Wave network
//-----------------------------------------------------------------------------
bool Security::HandleEncryptedMsg
(
	uint8 const* _data,
	uint32 const _length,
	uint32 const _instance	// = 1
)
{
	if( Node* node = GetNodeUnsafe() )
	{
		if( SecurityCmd_Network_Key_Verify == (SecurityCmd)_data[0] ) {
			if (node->isController()) {
				InheritSecurityScheme();
			} else {
				// FIXME: stop security time
				StopTimer();
			}
		} else if( SecurityCmd_Scheme_Report == (SecurityCmd)_data[0] ) {
			// Don't quite underewstand this phase, why does it encrypted?
			Log::Write(LogLevel_Error,"enscrypted scheme report");
		} else if( SecurityCmd_Scheme_Inherit == (SecurityCmd)_data[0] ) {
			// We joind another controller with security support
			if (_data[1] == SECURITY_SCHEME_0) {
				SendInheritReport(_data);
			} else {
				// unsupported scheme, ignore it
			}
		} else if( SecurityCmd_Command_Supported_Get == (SecurityCmd)_data[0] ) {
			// Send the commands which need security, for us, it is replication only
			SendCommandSupported();
		} else if( SecurityCmd_Command_Supported_Report == (SecurityCmd)_data[0] ) {
			// Receive the commands which should be sent with security
			for(int i=1;i<_length;i++) {
				node->EnableSecurity(_data[i]);
			}
		} else if( SecurityCmd_Network_Key_Set == (SecurityCmd)_data[0] ) {
			SaveNetworkKey(&_data[1]);
		} else {
			Log::Write(LogLevel_Error,"Security: Unknown command %d", _data[0]);
		}
	}
}

//-----------------------------------------------------------------------------
// <Security::CreateVars>
// Create the values managed by this command class
//-----------------------------------------------------------------------------
void Security::CreateVars
(
	uint8 const _instance
)
{
	if( Node* node = GetNodeUnsafe() )
	{
	}
}
