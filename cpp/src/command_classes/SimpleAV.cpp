//-----------------------------------------------------------------------------
//
//	SwitchBinary.cpp
//
//	Implementation of the Z-Wave COMMAND_CLASS_SWITCH_BINARY
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

#include "CommandClasses.h"
#include "SimpleAV.h"
#include "WakeUp.h"
#include "MultiInstance.h"
#include "Defs.h"
#include "Msg.h"
#include "Driver.h"
#include "Node.h"
#include "Log.h"

#include "ValueButton.h"
#include "ValueByte.h"

using namespace OpenZWave;

enum SimpleAVCmd
{
	SimpleAVCmd_Set		= 0x01,
	SimpleAVCmd_Get		= 0x02,
	SimpleAVCmd_Report	= 0x03,
	SimpleAVCmd_Learn	= 0x20,
	SimpleAVCmd_Supported_Get	= 0x04,
	SimpleAVCmd_Supported_Report	= 0x05
};

//-----------------------------------------------------------------------------
// <SimpleAV::RequestState>												   
// Request current state from the device									   
//-----------------------------------------------------------------------------
bool SimpleAV::RequestState
(
	uint32 const _requestFlags,
	uint8 const _instance,
	Driver::MsgQueue const _queue
)
{
	if( _requestFlags & RequestFlag_Static )
	{
		//return RequestValue( _requestFlags, 0, _instance, _queue );
	}

	return false;
}

//-----------------------------------------------------------------------------
// <SimpleAV::RequestValue>												   
// Request current value from the device									   
//-----------------------------------------------------------------------------
bool SimpleAV::RequestValue
(
	uint32 const _requestFlags,
	uint8 const _dummy1,	// = 0 (not used)
	uint8 const _instance,
	Driver::MsgQueue const _queue
)
{
	return false;
	Msg* msg = new Msg( "SimpleAVCmd_Get", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true,true,FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId() );
	msg->SetInstance( this, _instance );
	msg->Append( GetNodeId() );
	msg->Append( 2 );
	msg->Append( GetCommandClassId() );
	msg->Append( SimpleAVCmd_Get );
	msg->Append( GetDriver()->GetTransmitOptions() );
	GetDriver()->SendMsg( msg, _queue );
	return true;
}

//-----------------------------------------------------------------------------
// <SimpleAV::HandleMsg>
// Handle a message from the Z-Wave network
//-----------------------------------------------------------------------------
bool SimpleAV::HandleMsg
(
	uint8 const* _data,
	uint32 const _length,
	uint32 const _instance	// = 1
)
{
	Log::Write(LogLevel_Info,"data[0] = %d", _data[0]);
	Node* node = GetNodeUnsafe();
	if (node == NULL) return false;
	if (SimpleAVCmd_Report == (SimpleAVCmd)_data[0])
	{
		Log::Write( LogLevel_Info, GetNodeId(), "Received SimpleAV report from node %d: num of reports=%d", GetNodeId(), _data[1] );
		int i;


		for(i=0;i<_data[1];i++) {
			Msg* msg = new Msg( "SimpleAVCmd_Supported_Get", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true,true,FUNC_ID_APPLICATION_COMMAND_HANDLER, GetCommandClassId());
			msg->SetInstance( this, _instance );
			msg->Append( GetNodeId() );
			msg->Append( 3 );
			msg->Append( GetCommandClassId() );
			msg->Append( SimpleAVCmd_Supported_Get );
			msg->Append( i);
			msg->Append( GetDriver()->GetTransmitOptions() );
			GetDriver()->SendMsg( msg,Driver::MsgQueue_Send );
		}
	}
	if (SimpleAVCmd_Supported_Report == (SimpleAVCmd)_data[0]) {
		unsigned int start = 45*8+1;
		unsigned int i;
		unsigned int mask = 1;

		for(i=1;i<=(_length-3)*8;i++) {
			if (_data[3+(i-1)/8] & mask) {
				if( ValueButton* value = static_cast<ValueButton*>( GetValue( _instance, i+start ) ) )
				{
					value->Release();
				} else {
					node->CreateValueButton(ValueID::ValueGenre_User, GetCommandClassId(),_instance, i, "Button", 0);
				}
			}
			if (mask == 0x80)
				mask = 1;
			else
				mask = mask << 1;
		}
		ClearStaticRequest( StaticRequest_Values );
		return true;
	}

	return false;
}

//-----------------------------------------------------------------------------
// <SimpleAV::SetValue>
// Set the state of th
//-----------------------------------------------------------------------------
bool SimpleAV::SetValue
(
	Value const& _value
)
{
	int instance = _value.GetID().GetInstance();
	ValueByte const* value = static_cast<ValueByte const*>(&_value);
	int index = value->GetValue();

	Msg* msg = new Msg( "SimpleAV Set", GetNodeId(), REQUEST, FUNC_ID_ZW_SEND_DATA, true );		
	Log::Write(LogLevel_Info,"Index is %d instance %d", index,instance);
	if (instance > 30) {
		instance -= 30;
		msg->SetEndPoint( this, instance );
		msg->Append( GetNodeId() );
		msg->Append( 8);
		msg->Append(GetCommandClassId() );
		msg->Append(SimpleAVCmd_Set);
		msg->Append(m_seq++);
		msg->Append(1);				// Key Up
		msg->Append(0);
		msg->Append(0);
		msg->Append(index/256);
		msg->Append(index%256);
		msg->Append( GetDriver()->GetTransmitOptions() );
		GetDriver()->SendMsg( msg, Driver::MsgQueue_Send );
		return false;
	} else if (instance > 20) {
		instance -= 20;
		msg->SetEndPoint( this, instance + 10 );
		msg->Append( GetNodeId() );
		msg->Append( 8);
		msg->Append(GetCommandClassId() );
		msg->Append(SimpleAVCmd_Set);
		msg->Append(m_seq++);
		msg->Append(0);				// Learn IR
		msg->Append(0);
		msg->Append(0);
		msg->Append(index/256);
		msg->Append(index%256);
		msg->Append( GetDriver()->GetTransmitOptions() );
		GetDriver()->SendMsg( msg, Driver::MsgQueue_Send );
		return false;
	} else if (instance > 10) {
		Log::Write(LogLevel_Info,"send skeepalive to isnstance %d", instance);
		msg->SetEndPoint( this, instance-10);
		msg->Append( GetNodeId() );
		msg->Append( 8);
		msg->Append(GetCommandClassId() );
		msg->Append(SimpleAVCmd_Set);
		msg->Append(m_seq++);
		msg->Append(2);
		msg->Append(0);
		msg->Append(0);
		msg->Append(index/256);
		msg->Append(index%256);
		msg->Append( GetDriver()->GetTransmitOptions() );
		GetDriver()->SendMsg( msg, Driver::MsgQueue_Send );
		return false;
	} else {
		msg->SetEndPoint( this, instance );
		msg->Append( GetNodeId() );
		msg->Append( 8);
		msg->Append(GetCommandClassId() );
		msg->Append(SimpleAVCmd_Set);
		msg->Append(m_seq++);
		msg->Append(0);
		msg->Append(0);
		msg->Append(0);
		msg->Append(index/256);
		msg->Append(index%256);
		msg->Append( GetDriver()->GetTransmitOptions() );
		GetDriver()->SendMsg( msg, Driver::MsgQueue_Send );
		return false;
	}

}
//-----------------------------------------------------------------------------
// <SimpleAV::CreateVars>
// Create the values managed by this command class
//-----------------------------------------------------------------------------
void SimpleAV::CreateVars
(
	uint8 const _instance
)
{
	// Create values at report
	if( Node* node = GetNodeUnsafe() ) {
  		node->CreateValueByte( ValueID::ValueGenre_Basic, GetCommandClassId(), _instance, 0, "Send IR", "", false, false, 0, 0 );
  		node->CreateValueByte( ValueID::ValueGenre_Basic, GetCommandClassId(), _instance+10, 0, "Send IR keepalive", "", false, false, 0, 0 );
  		node->CreateValueByte( ValueID::ValueGenre_Basic, GetCommandClassId(), _instance+20, 255, "Learn IR", "", false, false, 0, 0 );
  		node->CreateValueByte( ValueID::ValueGenre_Basic, GetCommandClassId(), _instance+30, 0, "Send IR release", "", false, false, 0, 0 );
	}
}
