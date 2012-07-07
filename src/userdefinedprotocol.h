/***************************************************************************
  userdefinedprotocol.h  -
  -------------------
begin                : Fri Apr 20 14:56:00 CET 2001
copyright            : (C) 2000-2001 by Simon Edwards
email                : simon@simonzone.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#pragma once

#include <netinet/in.h>
#include <qstring.h>
#include <sstream>

#include "protocoldb.h"
//
// This class is basically a facade over the Protocol DB classes.
//
class UserDefinedProtocol
{
    uint id;
public:
    ProtocolEntry entry;
    ProtocolNetUse       netuse;
    ProtocolNetUseDetail destdetail;
public:
    /** 
    @brief: This function compares the internals of 2 protocols to determine if they are
            the same.
            This is needed to not readd the same protocol twice, when loading the same config
            twice. It will, however not prevent similar protocols from being added. (like
            if only the name is different)
    **/
    bool operator==(UserDefinedProtocol const & that) const
    {
        return entry == that.entry;
    }

    UserDefinedProtocol(std::string const & tmpstring, uchar udptype, uint udpstartport, uint udpendport, bool udpbidirectional, ProtocolDB & database, uint newid)
    {
        entry = ProtocolEntry() ;
        entry.classification = CLASS_CUSTOM;
        setID(newid);
        netuse =  ProtocolNetUse();
        netuse.type = IPPROTO_TCP;
        netuse.bidirectional = true;
        netuse.source = ENTITY_CLIENT;
        netuse.dest = ENTITY_SERVER;
        entry.addNetwork( netuse);

        ProtocolNetUseDetail sourcedetail;
        //sourcedetail.setAlternate( false );
        sourcedetail.setRangeType( PORTRANGE_ANY );
        sourcedetail.setStartPort( 1024 );
        sourcedetail.setEndPort( 65535 );
        netuse.addSource(sourcedetail);

        destdetail = ProtocolNetUseDetail();
        //destdetail.setAlternate( false );
        destdetail.setRangeType( PORTRANGE_RANGE );
        destdetail.setStartPort( 0 );
        destdetail.setEndPort( 0 );
        netuse.addDest(destdetail);

        setName(tmpstring);
        setType((uchar)udptype);
        setStartPort(udpstartport);
        setEndPort(udpendport);
        setBidirectional(udpbidirectional);

        database.addProtocolEntry(entry);
    }

    ~UserDefinedProtocol()
    {
        //    db->takeEntry(entry);
        //    delete entry;
    }

    void setID(uint newid)
    {
        id = newid;
        std::stringstream ss;
        ss << "userdefined" << id;
        entry.name = ss.str();
    }

    uint getID() const
    {
        return id;
    }

    void setName(const std::string &n)
    {
        entry.longname = n;
    }

    std::string getRangeString() const
    {
        return destdetail.getRangeString();
    }

    std::string getName() const
    {
        return entry.longname;
    }

    void setType(uchar t)
    {
        netuse.type = t;
    }

    uchar getType() const
    {
        return netuse.type;
    }

    void setBidirectional(bool on)
    {
        netuse.bidirectional = on;
    }

    bool isBidirectional() const
    {
        return netuse.isBidirectional();
    }

    void setStartPort(uint p)
    {
        destdetail.setStartPort( p );
    }

    void setEndPort(uint p)
    {
        destdetail.setEndPort( p );
    }

    uint getStartPort() const
    {
        return destdetail.getStart();
    }

    uint getEndPort() const
    {
        return destdetail.getEnd();
    }

    ProtocolEntry const & getProtocolEntry() const
    {
        return entry;
    }
};

