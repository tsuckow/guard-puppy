/***************************************************************************
                               protocoldb.h  -
                             -------------------
    begin                : Thu Nov 23 09:00:22 CET 2000
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
#ifndef PROTOCOLDB_H
#define PROTOCOLDB_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <netinet/tcp.h>
#ifdef QT_LITE
#include "qxml.h"
#include "qptrlist.h"
#include "qintdict.h"
#include "qstringlist.h"
#else
#include <qxml.h>
#include <qptrlist.h>
#include <qintdict.h>
#include <qprogressdialog.h>
#include <qstringlist.h>
#endif

/*

Here we go. A ProtocolDB object holds the whole protocol database. There
is usually only one instance of this. The ProtocolDB object holds a list of
ProtocolEntry objects. Each ProtocolEntry holds the info about one particualar
network protocol. In turn a ProtocolEntry object holds a list of
ProtocolNetUse objects. ProtocolNetUse objects hold information about one way
that the protocol uses the network. By this I mean something like a TCP
connection etc. For example. Looking at the diagram below which shows
troublesome normal FTP, we see that FTP uses two connections. One from the
Client to the Server to control the session, and one back from the server to
the client to transmit files.

  __________   Control      ___________
 /          \  ----TCP---> /           \
| FTP Client |            |  FTP Server |
 \__________/  <----TCP--- \___________/
                  Data

Each of these connections is represented in the database by a ProtocolNetUse
object describing what kind of IP protocol is used (TCP, UDP etc), which
party initiates the connection to who, and also what source/dest ports are
used etc.

The whole idea of the Protocol Database is to capture the info in diagrams
like the one above, instead of only just recording port numbers without any
info about how a protocol actually uses them.

*/

class ProtocolDB : public QXmlDefaultHandler {

public:
    ProtocolDB();
    ~ProtocolDB();

        // Just a tiny helper class.
    class PortRangeInfo {
    public:
        PortRangeInfo();
        ~PortRangeInfo();
        
        uint dynamicStart;
        uint dynamicEnd;
    };
    
    enum NetworkEntity {ENTITY_SERVER, ENTITY_CLIENT};
    enum Classification {CLASS_UNKNOWN=0,CLASS_MAIL,CLASS_CHAT,CLASS_FILE,
        CLASS_GAME,CLASS_SESSION,CLASS_DATA,CLASS_MEDIA,CLASS_NET,CLASS_CUSTOM};
    enum RangeType {PORTRANGE_RANGE=0,PORTRANGE_ANY,PORTRANGE_PRIVILEGED,
        PORTRANGE_NONPRIVILEGED,PORTRANGE_DYNAMIC};
   
    	// Holds a single port range.
    class ProtocolNetUseDetail {
    public:
        ProtocolNetUseDetail();
        ~ProtocolNetUseDetail();
        
        uint getStart(const PortRangeInfo *ri=0);
        uint getEnd(const PortRangeInfo *ri=0);
        
        bool alternate;
        RangeType rangetype;
        union {
        uint start; // tcmp, udp
        uint type;  // icmp
        };
        union {
        uint end;   // tcp, udp
        int code;   // icmp
        };
        void print();
    };

    class ProtocolNetUse {
    public:
        ProtocolNetUse();
        ~ProtocolNetUse();
        void print();
		bool sourcePortEquals(uint port);
		bool destPortEquals(uint port);
        bool icmpTypeCodeEquals(uint type, int code);
		
        QString descriptionlanguage;
        QString description;
        uchar type;	// IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP
        bool bidirectional;	// For UDP.
		NetworkEntity source;
		NetworkEntity dest;
		
        QList<ProtocolNetUseDetail> sourcedetaillist;	// A list of source port ranges.
        QList<ProtocolNetUseDetail> destdetaillist;		// A list of dest port ranges.

        QStringList pragmaname;  // Each string in here pairs up with a string
        QStringList pragmavalue; // in pragmavalue.
    };
    
    enum Score {SCORE_UNKNOWN=0,SCORE_LOW,SCORE_MEDIUM,SCORE_HIGH};

    class ProtocolEntry {
    public:
        ProtocolEntry();
        ~ProtocolEntry();
        void print();
    
        QString name;
        QString longnamelanguage;
        QString longname;
        
        QString descriptionlanguage;
        QString description;
    
        Score threat;
        Score falsepos;
        Classification classification;
        
        QList<ProtocolNetUse> networkuse;

        QStringList pragmaname;  // Each string in here pairs up with a string
        QStringList pragmavalue; // in pragmavalue.
    };
    
    bool loadDB(const QString &filename,const QStringList &languages);

        // XML processing
    bool startElement(const QString &namespaceURI, const QString &localName,
        const QString &qName, const QXmlAttributes &atts);
    bool endElement(const QString &namespaceURI, const QString &localName,
        const QString &qName);
    bool characters(const QString &ch);
    void setDocumentLocator(QXmlLocator *l);
    bool error(const QXmlParseException &exception);
    bool fatalError(const QXmlParseException &exception);
    bool warning(const QXmlParseException &exception);
    QString errorString();
    
    QList<ProtocolEntry> *lookup(uchar type, uint port);
    ProtocolEntry *lookup(const QString &name);
    QListIterator<ProtocolEntry> *newDatabaseIterator();
    
    void insertEntry(ProtocolEntry *entry);
    /* takeEntry() removes an entry from the DB and turns ownership of it over
       to the caller. i.e. the caller must 'delete' it.
    */
    bool takeEntry(ProtocolEntry *entry);
    
    /* Removes an entry from the DB and deletes it.
    */
    bool removeEntry(ProtocolEntry *entry);
    
private:
    QList <ProtocolEntry> db;
    QFile *xmlfile;
    QXmlLocator *xmllocator;
    ProtocolEntry *currententry;
    
	ProtocolNetUse *currentnetuse;
    ProtocolNetUseDetail *currentnetusedetail;
    
    // Go state machine go! XML parser states.
    enum ParserState {
        PROTOCOL_STATE_OUTSIDE,
        PROTOCOL_STATE_PROTOCOLDB,
        PROTOCOL_STATE_ENTRY,
        PROTOCOL_STATE_ENTRY_PRAGMA,
        PROTOCOL_STATE_LONGNAME,
        PROTOCOL_STATE_DESCRIPTION,
        PROTOCOL_STATE_NETWORK,
        PROTOCOL_STATE_TCP,
        PROTOCOL_STATE_UDP,
        PROTOCOL_STATE_ICMP,
        PROTOCOL_STATE_IP,
        PROTOCOL_STATE_IP_PRAGMA,
        PROTOCOL_STATE_IP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_PRAGMA,
        PROTOCOL_STATE_TCP_SOURCE,
        PROTOCOL_STATE_TCP_DEST,
        PROTOCOL_STATE_TCP_PRAGMA,
        PROTOCOL_STATE_UDP_SOURCE,
        PROTOCOL_STATE_UDP_DEST,
        PROTOCOL_STATE_UDP_PRAGMA,
        PROTOCOL_STATE_TCP_DESCRIPTION,
        PROTOCOL_STATE_UDP_DESCRIPTION,
        PROTOCOL_STATE_ICMP_DESCRIPTION,
        PROTOCOL_STATE_TCP_SOURCE_PORT,
        PROTOCOL_STATE_TCP_DEST_PORT,
        PROTOCOL_STATE_UDP_SOURCE_PORT,
        PROTOCOL_STATE_UDP_DEST_PORT,
        PROTOCOL_STATE_TCP_SOURCE_PORTRANGE,
        PROTOCOL_STATE_TCP_DEST_PORTRANGE,
        PROTOCOL_STATE_UDP_SOURCE_PORTRANGE,
        PROTOCOL_STATE_UDP_DEST_PORTRANGE,
        PROTOCOL_STATE_SECURITY,
        PROTOCOL_STATE_ICMP_TYPE,
        PROTOCOL_STATE_CLASSIFICATION,

        PROTOCOL_STATE_UNKNOWN,
        PROTOCOL_STATE_FINISHED
    };
    ParserState parsestate;
    
    	// XML parser error codes.
    enum ErrorState {
        PROTOCOL_ERROR_NOERROR,
        PROTOCOL_ERROR_OPEN_ERROR,
        PROTOCOL_ERROR_PARSE_ERROR,
        PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_TCP_DEST_UNKNOWN,
        PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_UDP_DEST_UNKNOWN,
        PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_ICMP_DEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND,
        PROTOCOL_ERROR_IP_SOURCE_UNKNOWN,
        PROTOCOL_ERROR_IP_DEST_UNKNOWN,
        PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT,
        PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE,
        PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT,
        PROTOCOL_ERROR_PORTRANGE_END_LESS_START,
        PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN,
        PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN,
        PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND,
        PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT,
        PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT,
        PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN
    };
    ErrorState errorstate;
    
    int unknowndepth;   // This is so that we can skip unknown tags.
    int numberoflines;
#ifndef QT_LITE
    QProgressDialog *progressdialog;
#endif    
	void printParseException(const QXmlParseException &exception);
	    
    QString protocolnamespace;
    QString linesattr;
    QString nameattr;
    QString portnumattr;
    QString portstartattr;
    QString portendattr;
    QString threatattr;
    QString falseposattr;
    QString sourceattr;
    QString destattr;
    QString directionattr;
    QString valueattr;
    QString codeattr;
    QString classattr;
    QString langattr;
    QString protocolattr;
    
    QString parseerror;
    QStringList languagelist;
    bool loaddescription;
    bool loadlongname;
            
    QIntDict< QList<ProtocolEntry> > porthash;
    void buildPortHash();
    void addEntryToPortHash(ProtocolEntry *entry);
    void removeEntryFromPortHash(ProtocolEntry *entry);
    long hashKey(uchar type, uint port);
    void addEntryToHash(ProtocolEntry *entry, uchar type, uint port);

    void doNetuseLanguage(const QXmlAttributes &atts);
};

#endif
