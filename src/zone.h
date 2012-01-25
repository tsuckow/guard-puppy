#pragma once

#include <string>
#include <vector>
#include <map>


class Zone 
{
public:
    enum ZoneType {LocalZone, InternetZone, UserZone};
    enum ProtocolState { PERMIT, DENY, REJECT };
private:
    std::string name;
    std::string comment;
    std::vector<IPRange> memberMachine;
    ZoneType             zonetype;
    std::map< std::string, std::map< std::string, ProtocolState > > protocols;
    std::vector< std::string > connections;          // List of zone names this zone is connected to
public:

    Zone( Zone const & rhs )
    {
        *this = rhs;
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

    Zone & operator=( Zone const & rhs )
    {
        name          = rhs.name;
        comment       = rhs.comment;
        memberMachine = rhs.memberMachine;
        zonetype      = rhs.zonetype;
        protocols     = rhs.protocols;

        return *this;
    }

    bool operator!=( Zone const & rhs ) const 
    { 
        return name != rhs.name; 
    }

    void setProtocolState( Zone const & clientzone, ProtocolDB::ProtocolEntry const & proto, Zone::ProtocolState state) 
    {
        //    ProtocolState currentstate;
        //QHash< void *, ProtocolDB::ProtocolEntry * >::const_iterator zoneinfo;
        //    QHash<void *, QHash<void *,ProtocolDB::ProtocolEntry *> >::iterator zoneinfo; 
        if ( isConnected( clientzone ) == false ) 
        {
            return;
        }

        //BTS new stuff...
        protocols[clientzone.name][proto.name] = state;
    }

    Zone(ZoneType zt) 
    {
        zonetype = zt;
    }

    ~Zone() 
    {
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
    
    ProtocolState getProtocolState(Zone const & clientzone, ProtocolDB::ProtocolEntry const & proto) 
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

    void denyAllProtocols( Zone const & clientzone ) 
    {
        if ( protocols.find( clientzone.name ) != protocols.end() )
        {
            protocols[ clientzone.name ].clear();
        }
    }

//    void deleteZone(Zone const & clientzone) 
//    {
//        disconnect(clientzone);
//    }

    ///////////////////////////////////////////////////////////////////////////
    void deleteProtocol(ProtocolDB::ProtocolEntry const & proto) 
    {
#if 0
        QPtrDictIterator< QPtrDict<ProtocolDB::ProtocolEntry> > *it;

        it = new QPtrDictIterator< QPtrDict<ProtocolDB::ProtocolEntry> >(servedprotocols);
        for(;it->current(); ++(*it)) {
            setProtocolState((Zone *)it->currentKey(),proto,DENY);
        }
        delete it;
#endif
    }

    bool isLocal() const
    {
        return zonetype==LocalZone;
    }

    bool isInternet() const 
    {
        return zonetype==InternetZone;
    }

    void connect( Zone const & clientzone ) 
    {
        // BTS  check for zone already in connection...
        connections.push_back( clientzone.getName() );
        //    if ( isConnected(clientzone) ) {
        //        return;
        //    }
        //    servedprotocols.insert((void *)clientzone, QHash<void *, ProtocolDB::ProtocolEntry *>());
        //    rejectedprotocols.insert((void *)clientzone, QHash<void *, ProtocolDB::ProtocolEntry *>());
    }

    void disconnect(Zone const & clientzone) 
    {
        //    protocols.erase(clientzone.name);
    }

    bool isConnected(Zone const & clientzone) 
    {
        return protocols.find( clientzone.name ) != protocols.end();
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

