/***************************************************************************
                          guarddog.cpp  -  description
                             -------------------
    begin                : Thu Feb 10 20:57:36 EST 2000
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

#include "userdefinedprotocol.h"

///////////////////////////////////////////////////////////////////////////
UserDefinedProtocol::UserDefinedProtocol(ProtocolDB *database, uint newid) {
    ProtocolDB::ProtocolNetUseDetail *sourcedetail;
    
    db = database;
    
    entry = new ProtocolDB::ProtocolEntry();
    entry->classification = ProtocolDB::CLASS_CUSTOM;
    setID(newid);
    netuse =  new ProtocolDB::ProtocolNetUse();
    netuse->type = IPPROTO_TCP;
    netuse->bidirectional = true;
    netuse->source = ProtocolDB::ENTITY_CLIENT;
    netuse->dest = ProtocolDB::ENTITY_SERVER;
    entry->networkuse.append(netuse);

    sourcedetail = new ProtocolDB::ProtocolNetUseDetail();
    sourcedetail->alternate = false;
    sourcedetail->rangetype = ProtocolDB::PORTRANGE_ANY;
    sourcedetail->start = 1024;
    sourcedetail->end = 65535;
    netuse->sourcedetaillist.append(sourcedetail);

    destdetail = new ProtocolDB::ProtocolNetUseDetail();
    destdetail->alternate = false;
    destdetail->rangetype = ProtocolDB::PORTRANGE_RANGE;
    destdetail->start = 0;
    destdetail->end = 0;
    netuse->destdetaillist.append(destdetail);
    
    db->insertEntry(entry);
}

///////////////////////////////////////////////////////////////////////////
UserDefinedProtocol::~UserDefinedProtocol() {
    db->takeEntry(entry);
    delete entry;
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setID(uint newid) {
    id = newid;
    entry->name = QString("userdefined%1").arg(id);
}

///////////////////////////////////////////////////////////////////////////
uint UserDefinedProtocol::getID() const {
    return id;
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setName(const QString &n) {
    entry->longname = n;
}

///////////////////////////////////////////////////////////////////////////
QString UserDefinedProtocol::getRangeString() {
    QString result;
    if (destdetail->start == destdetail->end)
        result.sprintf("%d", destdetail->start);
    else
        result.sprintf("%d:%d", destdetail->start, destdetail->end);
    return result;
}

///////////////////////////////////////////////////////////////////////////
QString UserDefinedProtocol::getName() const {
    return entry->longname;
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setType(uchar t) {
    netuse->type = t;
}

///////////////////////////////////////////////////////////////////////////

uchar UserDefinedProtocol::getType() const {
    return netuse->type;
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setBidirectional(bool on) {
    netuse->bidirectional = on;
}

///////////////////////////////////////////////////////////////////////////
bool UserDefinedProtocol::isBidirectional() const {
    return (netuse->type==IPPROTO_TCP) || netuse->bidirectional;
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setStartPort(uint p) {
    destdetail->start = p;
    if(destdetail->start > destdetail->end) {
        destdetail->end = p;
    }
}

///////////////////////////////////////////////////////////////////////////
void UserDefinedProtocol::setEndPort(uint p) {
    destdetail->end = p;
    if(destdetail->start > destdetail->end) {
        destdetail->start = p;
    }
}

///////////////////////////////////////////////////////////////////////////
uint UserDefinedProtocol::getStartPort() const {
    return destdetail->start;
}
    
///////////////////////////////////////////////////////////////////////////
uint UserDefinedProtocol::getEndPort() const {
    return destdetail->end;
}
    
///////////////////////////////////////////////////////////////////////////
ProtocolDB::ProtocolEntry *UserDefinedProtocol::getProtocolEntry() const {
    return entry;
}
