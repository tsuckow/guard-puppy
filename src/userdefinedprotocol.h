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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <qstring.h>
#include "protocoldb.h"

//
// This class is basically a facade over the Protocol DB classes.
//
class UserDefinedProtocol {
public:
    UserDefinedProtocol(ProtocolDB *database, uint newid);
    ~UserDefinedProtocol();

    void setID(uint newid);
    uint getID() const;
        
    void setName(const QString &n);
    QString getName() const;
    
    void setType(uchar t);
    uchar getType() const;

    void setBidirectional(bool on);
    bool isBidirectional() const;

    void setStartPort(uint p);
    uint getStartPort() const;
    void setEndPort(uint p);
    uint getEndPort() const;
    QString getRangeString();
    ProtocolDB::ProtocolEntry *getProtocolEntry() const;
    
private:
    uint id;
    ProtocolDB *db;
    ProtocolDB::ProtocolEntry *entry;
    ProtocolDB::ProtocolNetUse *netuse;
    ProtocolDB::ProtocolNetUseDetail *destdetail;
};

#endif
