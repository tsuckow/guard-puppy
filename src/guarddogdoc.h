/***************************************************************************
                          guarddogdoc.h  -  description
                             -------------------
    begin                : Thu Feb 10 20:57:36 EST 2000
    copyright            : (C) 2000-2006 by Simon Edwards
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

#ifndef GUARDDOGDOC_H
#define GUARDDOGDOC_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

// include files for QT
#ifndef QT_LITE
#include <qstring.h>
#include <qptrlist.h>
#include <qptrdict.h>
#include <qstringlist.h>
#include <qtextstream.h>
#else
#include "qstring.h"
#include "qptrlist.h"
#include "qptrdict.h"
#include "qstringlist.h"
#include "qtextstream.h"
#include "dummylocale.h"
#endif

#include "protocoldb.h"
#include "userdefinedprotocol.h"
#include "iprange.h"

class GuarddogDoc {

public:
    GuarddogDoc(ProtocolDB *database);
    ~GuarddogDoc();
        
    enum ZoneType {LocalZone, InternetZone, UserZone};
    
    class Zone;
    class Zone {
    public:
        Zone(ZoneType zt);
        ~Zone();
        QString name;
        QString comment;
        QList<IPRange> membermachine;
        
        bool editable();
        bool isLocal();
        bool isInternet();

        void connect(Zone *clientzone);
        void disconnect(Zone *clientzone);
        bool isConnected(Zone *clientzone);
        bool isConnectionMutable(Zone *clientzone);

        void enableProtocol(Zone *clientzone, ProtocolDB::ProtocolEntry *proto);    // DEPRECIATED
        void disableProtocol(Zone *clientzone, ProtocolDB::ProtocolEntry *proto);   // DEPRECIATED
        void disableAllProtocols(Zone *clientzone);                                 // DEPRECIATED
        bool isProtocolEnabled(Zone *clientzone, ProtocolDB::ProtocolEntry *proto); // DEPRECIATED
        
        enum ProtocolState {PERMIT, DENY, REJECT};
        
        void setProtocolState(Zone *clientzone, ProtocolDB::ProtocolEntry *proto, ProtocolState state);
        ProtocolState getProtocolState(Zone *clientzone, ProtocolDB::ProtocolEntry *proto);
        void denyAllProtocols(Zone *clientzone);
                        
        void deleteZone(Zone *clientzone);
        void deleteProtocol(ProtocolDB::ProtocolEntry *proto);
        
        QPtrDictIterator<ProtocolDB::ProtocolEntry> *newProtocolZoneIterator(Zone *clientzone); // DEPRECIATED

        QPtrDictIterator<ProtocolDB::ProtocolEntry> *newPermitProtocolZoneIterator(Zone *clientzone);
        QPtrDictIterator<ProtocolDB::ProtocolEntry> *newRejectProtocolZoneIterator(Zone *clientzone);

    private:
        ZoneType zonetype;
            // Dictionary mapping Zone pointers to dictionaries mapping protocolentries to protocolentries.
        QPtrDict< QPtrDict<ProtocolDB::ProtocolEntry> > servedprotocols;    // If a zone/protocol has
            // an entry in here then it means that the given protocol is Accepted for the given zone.
            
        QPtrDict< QPtrDict<ProtocolDB::ProtocolEntry> > rejectedprotocols;  // If a zone/protocol has
            // an entry in here then it means that the given protocol is Rejected for the given zone.
        
    };
    QListIterator<Zone> *newZonesIterator();
    Zone *zoneAt(int index);
    void deleteZone(Zone *thiszone);
    Zone *newZone();

    bool writeFirewall(QTextStream &stream, QString &errorstring);
    void writeIPChainsFirewall(QTextStream &stream);
    void writeIPTablesFirewall(QTextStream &stream);
    bool readFirewall(QTextStream &stream, QString &errorstring);

    bool openFirewall(const QString &filename,QString &errorstring);
    bool saveFirewall(const QString &filename, QString &errorstring);

    void setLocalDynamicPortRange(uint start,uint end);
    void getLocalDynamicPortRange(uint &start,uint &end);

    void setDisabled(bool on);
    bool isDisabled();
    void setLogDrop(bool on);
    bool isLogDrop();
    void setLogReject(bool on);
    bool isLogReject();
    void setLogIPOptions(bool on);
    bool isLogIPOptions();
    void setLogTCPOptions(bool on);
    bool isLogTCPOptions();
    void setLogTCPSequence(bool on);
    bool isLogTCPSequence();
    void setLogAbortedTCP(bool on);
    bool isLogAbortedTCP();
    void setLogLevel(uint level);
    uint getLogLevel();
    void setLogRateLimit(bool on);
    bool isLogRateLimit();
    void setLogRate(uint hitsper);
    uint getLogRate();
    enum LogRateUnit {SECOND=0, MINUTE, HOUR, DAY};
    void setLogRateUnit(LogRateUnit unit);
    LogRateUnit getLogRateUnit();
    void setLogRateBurst(uint burst);
    uint getLogRateBurst();
    void setLogWarnLimit(bool on);
    bool isLogWarnLimit();
    void setLogWarnLimitRate(uint hitsper);
    uint getLogWarnLimitRate();
    void setLogWarnLimitRateUnit(LogRateUnit unit);
    LogRateUnit getLogWarnLimitRateUnit();
    void setDHCPcEnabled(bool on);
    bool isDHCPcEnabled();
    void setDHCPcInterfaceName(const QString &ifacename);
    QString getDHCPcInterfaceName();
    void setDHCPdEnabled(bool on);
    bool isDHCPdEnabled();
    void setDHCPdInterfaceName(const QString &ifacename);
    QString getDHCPdInterfaceName();
    void setAllowTCPTimestamps(bool on);
    bool isAllowTCPTimestamps();
    
    void factoryDefaults();

    QListIterator<UserDefinedProtocol> *newUserDefinedProtocolsIterator();
    UserDefinedProtocol *userDefinedProtocolAt(int index);
    void deleteUserDefinedProtocol(UserDefinedProtocol *thisudp);
    UserDefinedProtocol *newUserDefinedProtocol();
    uint countUserDefinedProtocols();

    QString description;

private:
    ProtocolDB *pdb;
    QList <Zone> zones;

    void expandIPChainsFilterRule(QTextStream &stream,int fromzone,
        ProtocolDB::PortRangeInfo *fromzonePRI,int tozone,ProtocolDB::PortRangeInfo *tozonePRI,
        ProtocolDB::ProtocolNetUse &netuse, bool permit=true, bool log=false);

    void expandIPTablesFilterRule(QTextStream &stream,int fromzone,
        ProtocolDB::PortRangeInfo *fromzonePRI,int tozone,ProtocolDB::PortRangeInfo *tozonePRI,
        ProtocolDB::ProtocolNetUse &netuse, bool permit=true, bool log=false);

    uint localPortRangeStart;
    uint localPortRangeEnd;
    bool disabled;
    bool routing;

    bool logdrop;
    bool logreject;
    bool logipoptions;
    bool logtcpoptions;
    bool logtcpsequence;
    bool logabortedtcp;
    uint loglevel;
    bool logratelimit;
    uint lograte;
    LogRateUnit lograteunit;
    uint lograteburst;
    bool logwarnlimit;
    uint logwarnrate;
    LogRateUnit logwarnrateunit;
    bool dhcpcenabled;
    QString dhcpcinterfacename;
    bool dhcpdenabled;
    QString dhcpdinterfacename;
    bool allowtcptimestamps;

    void clearFirewall();

    QList <UserDefinedProtocol> userdefinedprotocols;
};

#endif // GUARDDOGDOC_H
