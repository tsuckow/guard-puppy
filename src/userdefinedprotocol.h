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
#ifndef USERDEFINEDPROTOCOL_H
#define USERDEFINEDPROTOCOL_H

#include <netinet/in.h>
#include <qstring.h>
#include "protocoldb.h"

#include <sstream>
//
// This class is basically a facade over the Protocol DB classes.
//
class UserDefinedProtocol {
public:
    //UserDefinedProtocol(ProtocolDB *database, uint newid) {
    UserDefinedProtocol(uint newid) 
    {

        //    db = database;

        entry = ProtocolDB::ProtocolEntry() ;
        entry.classification = ProtocolDB::CLASS_CUSTOM;
        setID(newid);
        netuse =  ProtocolDB::ProtocolNetUse();
        netuse.type = IPPROTO_TCP;
        netuse.bidirectional = true;
        netuse.source = ProtocolDB::ENTITY_CLIENT;
        netuse.dest = ProtocolDB::ENTITY_SERVER;
        entry.networkuse.push_back(netuse);

        ProtocolDB::ProtocolNetUseDetail sourcedetail;
        sourcedetail.alternate = false;
        sourcedetail.rangetype = ProtocolDB::PORTRANGE_ANY;
        sourcedetail.start = 1024;
        sourcedetail.end = 65535;
        netuse.sourcedetaillist.push_back(sourcedetail);

        destdetail = ProtocolDB::ProtocolNetUseDetail();
        destdetail.alternate = false;
        destdetail.rangetype = ProtocolDB::PORTRANGE_RANGE;
        destdetail.start = 0;
        destdetail.end = 0;
        netuse.destdetaillist.push_back(destdetail);

        //    db->insertEntry(entry);
    }

    ///////////////////////////////////////////////////////////////////////////
    ~UserDefinedProtocol() {
        //    db->takeEntry(entry);
        //    delete entry;
    }

    ///////////////////////////////////////////////////////////////////////////
    void setID(uint newid) {
        id = newid;
        std::stringstream ss;
        ss << "userdefined" << id;
        entry.name = ss.str();
    }

    ///////////////////////////////////////////////////////////////////////////
    uint getID() const {
        return id;
    }

    ///////////////////////////////////////////////////////////////////////////
    void setName(const std::string &n) {
        entry.longname = n;
    }

    ///////////////////////////////////////////////////////////////////////////
    std::string getRangeString() const {
        std::stringstream result;
        if (destdetail.start == destdetail.end)
            result << destdetail.start;
        else
            result << destdetail.start << ":" << destdetail.end;
        return result.str();
    }

    ///////////////////////////////////////////////////////////////////////////
    std::string getName() const {
        return entry.longname;
    }

    ///////////////////////////////////////////////////////////////////////////
    void setType(uchar t) {
        netuse.type = t;
    }

    ///////////////////////////////////////////////////////////////////////////

    uchar getType() const {
        return netuse.type;
    }

    ///////////////////////////////////////////////////////////////////////////
    void setBidirectional(bool on) {
        netuse.bidirectional = on;
    }

    ///////////////////////////////////////////////////////////////////////////
    bool isBidirectional() const {
        return (netuse.type==IPPROTO_TCP) || netuse.bidirectional;
    }

    ///////////////////////////////////////////////////////////////////////////
    void setStartPort(uint p) {
        destdetail.start = p;
        if(destdetail.start > destdetail.end) {
            destdetail.end = p;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    void setEndPort(uint p) {
        destdetail.end = p;
        if(destdetail.start > destdetail.end) {
            destdetail.start = p;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    uint getStartPort() const {
        return destdetail.start;
    }

    ///////////////////////////////////////////////////////////////////////////
    uint getEndPort() const {
        return destdetail.end;
    }

    ///////////////////////////////////////////////////////////////////////////
    ProtocolDB::ProtocolEntry const & getProtocolEntry() const {
        return entry;
    }    
private:
    uint id;
    //    ProtocolDB *db;
public:
    ProtocolDB::ProtocolEntry entry;
private:
    ProtocolDB::ProtocolNetUse netuse;
    ProtocolDB::ProtocolNetUseDetail destdetail;
};

#endif
