#pragma once

#include <string>
#include <vector>
#include <map>

#include <boost/foreach.hpp>
#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>

#include "iprange.h"

class Zone 
{
public:
    enum ZoneType {LocalZone, InternetZone, UserZone};
    enum ProtocolState { PERMIT, DENY, REJECT };
private:
    std::string name;
    std::string comment;
    ZoneType    zonetype;
    std::vector<IPRange> memberMachine;
    std::map< std::string, std::map< std::string, ProtocolState > > protocols;  // [toZone][protocolName] = state
    std::vector< std::string > connections;          // List of zone names this zone is connected to
    unsigned int id;
    static unsigned int nextId;
public:

    Zone( Zone const & rhs )
    {
        *this = rhs;
    }

    Zone( ZoneType zt ) 
    {
        zonetype = zt;
        id = nextId++;
    }

    Zone( std::string const & zoneName, ZoneType zt = UserZone )
     : name( zoneName ), zonetype( zt )
    {
        id = nextId++;
    }

    ~Zone() 
    {
    }

    Zone & operator=( Zone const & rhs )
    {
        name          = rhs.name;
        comment       = rhs.comment;
        memberMachine = rhs.memberMachine;
        zonetype      = rhs.zonetype;
        protocols     = rhs.protocols;
        id            = rhs.id;

        return *this;
    }

    unsigned int getId() const { return id; }

    void renameMachine( std::string const & oldMachineName, std::string const & newMachineName )
    {
        std::vector< IPRange >::iterator i = std::find_if( memberMachine.begin(), memberMachine.end(), boost::phoenix::bind( &IPRange::getAddress, boost::phoenix::arg_names::arg1) == oldMachineName );    

        if ( i != memberMachine.end() )
            i->setAddress( newMachineName );
    }

    void setComment( std::string const & c )
    {
        comment = c;
    }

    std::string const & getComment() const
    {
        return comment;
    }

    void setName( std::string const & n )
    {
        name = n;
    }
    std::string const & getName() const
    {
        return name;
    }

    std::vector<IPRange> const & getMemberMachineList() const
    {
        return memberMachine;
    }

    void addMemberMachine( IPRange const & ip )
    {
        memberMachine.push_back( ip );
    }

    void deleteMemberMachine( IPRange const & ip )
    {
        std::vector<IPRange>::iterator i = std::find( memberMachine.begin(), memberMachine.end(), ip );
        if ( i != memberMachine.end() )
            memberMachine.erase( i );
    }

    bool operator!=( Zone const & rhs ) const 
    { 
        return name != rhs.name; 
    }

    void setProtocolState( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state) 
    {
        std::cout << "setProtocolState " << name << " to " << zoneTo << " for " << protocol << " " << state << std::endl;
        protocols[ zoneTo ][ protocol ] = state;
    }

    void setProtocolState( Zone const & clientzone, ProtocolEntry const & proto, Zone::ProtocolState state) 
    {
        std::cout << "setProtocolState " << name << " to " << clientzone.name << " for " << proto.name << " " << state << std::endl;
        protocols[clientzone.name][proto.name] = state;
    }

    bool editable() const 
    {
        switch ( zonetype ) 
        {
            case LocalZone:
            case InternetZone:
                return false;
            default:
                return true;
        }
    }

    ProtocolState getProtocolState( std::string const & toZone, std::string const & protocolName ) const
    {
        std::map< std::string, std::map< std::string, ProtocolState > >::const_iterator zit;
        zit = protocols.find( toZone );
        if ( zit == protocols.end() )
            return DENY;
        std::map< std::string, ProtocolState >::const_iterator pit;
        pit = zit->second.find( protocolName );
        if ( pit == zit->second.end() )
            return DENY;
        return pit->second;

    }

    std::vector< std::string > getConnectedZoneProtocols( std::string const & toZone, ProtocolState state ) const
    {
        std::cout << "Looking for protocols from " << name << " to " << toZone << " in state " << state << std::endl;
        std::vector< std::string > protocolsNames;
        typedef std::map< std::string, ProtocolState > map_t;

        std::map< std::string, map_t >::const_iterator zit;
        zit = protocols.find( toZone );
        if ( zit != protocols.end() )
        {
            BOOST_FOREACH( map_t::value_type const & mapEntry, zit->second )
            {
                if ( mapEntry.second == state )
                    protocolsNames.push_back( mapEntry.first );
            }
        }
        return protocolsNames;
    }
    
#if 0
    ProtocolState getProtocolState(Zone const & clientzone, ProtocolEntry const & proto) 
    {
        if ( protocols.find( clientzone.name ) != protocols.end() )
        {
            if ( protocols[clientzone.name].find( proto.name ) != protocols[clientzone.name].end() )
            {
                return protocols[clientzone.name][proto.name];
            }
        }
        return DENY;
    }
#endif
    void denyAllProtocols( Zone const & clientzone ) 
    {
        if ( protocols.find( clientzone.name ) != protocols.end() )
        {
            protocols[ clientzone.name ].clear();
        }
    }

    bool isLocal() const
    {
        return zonetype==LocalZone;
    }

    bool isInternet() const 
    {
        return zonetype==InternetZone;
    }

    void connect( std::string const & zoneTo ) 
    {
        std::cout << "Connecting zone " << name << " to " << zoneTo << std::endl;
        if ( !isConnected( zoneTo ) )
        {
            connections.push_back( zoneTo );
        }
    }

    void disconnect( std::string const & zoneTo )
    {
        std::cout << "Disconnecting zone " << name << " to " << zoneTo << std::endl;
        std::vector< std::string >::iterator i = std::find( connections.begin(), connections.end(), zoneTo );
        if ( i != connections.end() )
        {
            connections.erase( i );
        }
    }

    bool isConnected( std::string const & zoneName ) const
    {
        return std::find( connections.begin(), connections.end(), zoneName ) != connections.end();
    }

    bool isConnectionMutable(Zone const & clientzone) 
    {
        if(isLocal() && clientzone.isInternet()) {
            return false;
        }
        if(isInternet() && clientzone.isLocal()) {
            return false;
        }
        return true;
    }
};

