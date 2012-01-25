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
//#include "qxml.h"
//#include "qptrlist.h"
//#include "qintdict.h"
//#include "qstringlist.h"
#else
//#include <qxml.h>
//#include <qptrlist.h>
//#include <qintdict.h>
//#include <qprogressdialog.h>
//#include <qstringlist.h>
#endif

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include <QXmlDefaultHandler>
#include <QHash>

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

class ProtocolDB : public QXmlDefaultHandler 
{

public:
        // Just a tiny helper class.
    class PortRangeInfo 
    {
    public:
        
        uint dynamicStart;
        uint dynamicEnd;
    PortRangeInfo() 
    {
        dynamicStart = 1024;
        dynamicEnd = 65535;
    }
    ~PortRangeInfo() 
    {
    }

    };
    
    enum NetworkEntity {ENTITY_SERVER, ENTITY_CLIENT};
    enum Classification {CLASS_UNKNOWN=0,CLASS_MAIL,CLASS_CHAT,CLASS_FILE,
        CLASS_GAME,CLASS_SESSION,CLASS_DATA,CLASS_MEDIA,CLASS_NET,CLASS_CUSTOM};
    enum RangeType {PORTRANGE_RANGE=0,PORTRANGE_ANY,PORTRANGE_PRIVILEGED,
        PORTRANGE_NONPRIVILEGED,PORTRANGE_DYNAMIC};
   
    	// Holds a single port range.
    class ProtocolNetUseDetail {
    public:
        
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


ProtocolNetUseDetail() {
    alternate = false;
    rangetype = PORTRANGE_RANGE;
    start = 0;
    end = 0;
}

///////////////////////////////////////////////////////////////////////////
~ProtocolNetUseDetail() {

}

///////////////////////////////////////////////////////////////////////////
uint getStart(const PortRangeInfo *ri = 0) 
{
    switch(rangetype) {
        case PORTRANGE_RANGE:
            return start;
        case PORTRANGE_ANY:
            return 0;
        case PORTRANGE_PRIVILEGED:
            return 0;
        case PORTRANGE_NONPRIVILEGED:
            return 1024;
        case PORTRANGE_DYNAMIC:
        default:
            return ri==0 ? 1024 : ri->dynamicStart;
    }
}

///////////////////////////////////////////////////////////////////////////
uint getEnd(const PortRangeInfo *ri = 0) 
{
    switch(rangetype) {
        case PORTRANGE_RANGE:
            return end;
        case PORTRANGE_ANY:
            return 65535;
        case PORTRANGE_PRIVILEGED:
            return 1023;
        case PORTRANGE_NONPRIVILEGED:
            return 65535;
        case PORTRANGE_DYNAMIC:
        default:
            return ri==0 ? 65535 : ri->dynamicEnd;
    }
}

///////////////////////////////////////////////////////////////////////////
void print() const {
    fprintf(stderr,"[ Alternate: %d Start: %u End: %u ]",
        (int)alternate,start,end);
}



    };

    class ProtocolNetUse {
    public:
//		bool sourcePortEquals(uint port);
//		bool destPortEquals(uint port);
 //       bool icmpTypeCodeEquals(uint type, int code);
		
        std::string descriptionlanguage;
        std::string description;
        uchar type;	// IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP
        bool bidirectional;	// For UDP.
		NetworkEntity source;
		NetworkEntity dest;
		
        QList<ProtocolNetUseDetail> sourcedetaillist;	// A list of source port ranges.
        QList<ProtocolNetUseDetail> destdetaillist;		// A list of dest port ranges.

        std::vector< std::string > pragmaname;          // Each string in here pairs up with a string
        std::vector< std::string > pragmavalue;         // in pragmavalue.

ProtocolNetUse() {
//    sourcedetaillist.setAutoDelete(true);
//    destdetaillist.setAutoDelete(true);
    source = ENTITY_CLIENT;
    dest = ENTITY_SERVER;
    bidirectional = false;
}

///////////////////////////////////////////////////////////////////////////
~ProtocolNetUse() {

}

///////////////////////////////////////////////////////////////////////////
void print() const {

    fprintf(stderr,"[Description: %s ",(const char *)description.c_str());
    switch(type) {
        case IPPROTO_TCP:
            fprintf(stderr," Type: tcp ");
            break;

        case IPPROTO_UDP:
            fprintf(stderr," Type: udp ");
            break;

        case IPPROTO_ICMP:
            fprintf(stderr," Type: icmp ");
            break;
            
        default:
            fprintf(stderr," Type: %d ",(int)type);
            break;
    }
    fprintf(stderr," Source: ");
    BOOST_FOREACH( ProtocolNetUseDetail const & x, sourcedetaillist ) {
//    for(x=sourcedetaillist.first(); x!=0; x=sourcedetaillist.next()) {
        x.print();
    }
    fprintf(stderr," Dest: ");
    BOOST_FOREACH( ProtocolNetUseDetail const & x, destdetaillist ) {
//    for(x=destdetaillist.first(); x!=0; x=destdetaillist.next()) {
        x.print();
    }
    fprintf(stderr,"]");
}
///////////////////////////////////////////////////////////////////////////
bool sourcePortEquals(uint port) {
    
//    p=sourcedetaillist.first();
    if(sourcedetaillist.empty()) {
        return true;    //An empty list matches anything.
    }
    BOOST_FOREACH( ProtocolNetUseDetail const & p, sourcedetaillist ) {
//    for(; p!=0; p=sourcedetaillist.next()) {
        if(port>=p.start && port<=p.end) {    // It must be in range.
            return true;
        }
    }
    return false;
}
///////////////////////////////////////////////////////////////////////////
bool destPortEquals(uint port) {
    
//    p=destdetaillist.first();
//    if(p==0) {
    if ( destdetaillist.empty() ) {
        return true;    // An empty list matches anything.
    }
    BOOST_FOREACH( ProtocolNetUseDetail const & p, destdetaillist ) {
//    for(; p!=0; p=destdetaillist.next()) {
        if(port>=p.start && port<=p.end) {
            return true;
        }
    }
    return false;
}
///////////////////////////////////////////////////////////////////////////
bool icmpTypeCodeEquals(uint type, int code) {
    
    BOOST_FOREACH( ProtocolNetUseDetail const & p, sourcedetaillist ) {
//    for(p=sourcedetaillist.first(); p!=0; p=sourcedetaillist.next()) {
        if(type==p.type) {
            if(p.code==-1) {    // -1 is the wild card.
                return true;
            } else {
                if(p.code==code) {
                    return true;
                }
            }
        }
    }
    return false;
}


    };
    
    enum Score {SCORE_UNKNOWN=0,SCORE_LOW,SCORE_MEDIUM,SCORE_HIGH};

    class ProtocolEntry {
    public:
        std::string name;
        std::string longnamelanguage;
        std::string longname;
        
        std::string descriptionlanguage;
        std::string description;
    
        Score threat;
        Score falsepos;
        Classification classification;
        
        QList<ProtocolNetUse> networkuse;

        std::vector< std::string > pragmaname;  // Each string in here pairs up with a string
        std::vector< std::string > pragmavalue; // in pragmavalue.

ProtocolEntry() {
//    networkuse.setAutoDelete(true);
    threat = SCORE_UNKNOWN;
    falsepos = SCORE_UNKNOWN;
    classification = CLASS_UNKNOWN;
}

///////////////////////////////////////////////////////////////////////////
~ProtocolEntry() {

}
///////////////////////////////////////////////////////////////////////////
void print() const {

    fprintf(stderr,"[ Name: %s Longname: %s Threat: ",name.c_str(),longname.c_str());
    switch(threat) {
        case SCORE_LOW:
            fprintf(stderr,"low");
            break;
        case SCORE_MEDIUM:
            fprintf(stderr,"medium");
            break;
        case SCORE_HIGH:
            fprintf(stderr,"high");
            break;
        default:
            fprintf(stderr,"unknown");
            break;
    }
    fprintf(stderr," Classification: ");
    switch(classification) {
        case CLASS_UNKNOWN:
            fprintf(stderr,"unknown");
            break;
            
        case CLASS_MAIL:
            fprintf(stderr,"mail");
            break;
            
        case CLASS_CHAT:
            fprintf(stderr,"chat");
            break;
            
        case CLASS_FILE:
            fprintf(stderr,"file");
            break;
            
        case CLASS_GAME:
            fprintf(stderr,"game");
            break;
            
        case CLASS_SESSION:
            fprintf(stderr,"session");
            break;
            
        case CLASS_DATA:
            fprintf(stderr,"data");
            break;
            
        case CLASS_MEDIA:
            fprintf(stderr,"media");
            break;
            
        case CLASS_NET:
            fprintf(stderr,"net");
            break;
            
        default:
            break;
    }
    
    BOOST_FOREACH( ProtocolNetUse const & x, networkuse ) {
//    for(x=networkuse.first(); x!=0; x=networkuse.next()) {
        x.print();
    }
    fprintf(stderr,"]");
}



    };
    
    QList<ProtocolEntry *>::iterator lookup(uchar type, uint port);
    std::vector< ProtocolEntry >::const_iterator dbEnd() const { return db.end(); }
//    QListIterator<ProtocolEntry> *newDatabaseIterator();
    
private:
    std::vector< ProtocolEntry > db;
    QXmlLocator *xmllocator;
    ProtocolEntry currententry;
    
	ProtocolNetUse currentnetuse;
    ProtocolNetUseDetail currentnetusedetail;
    
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
//    QProgressDialog *progressdialog;
#endif    
    std::string protocolnamespace;
    std::string linesattr;
    std::string nameattr;
    std::string portnumattr;
    std::string portstartattr;
    std::string portendattr;
    std::string threatattr;
    std::string falseposattr;
    std::string sourceattr;
    std::string destattr;
    std::string directionattr;
    std::string valueattr;
    std::string codeattr;
    std::string classattr;
    std::string langattr;
    std::string protocolattr;
    
    std::vector< std::string > parseerror;
    std::vector<std::string> languagelist;
    bool loaddescription;
    bool loadlongname;
            
    QHash< int, QList<ProtocolEntry * > > porthash;
public:
ProtocolDB( std::string const & filename ) :  protocolnamespace(""),
                            linesattr("lines"),
                            nameattr("name"),
                            portnumattr("portnum"),
                            portstartattr("start"),
                            portendattr("end"),
                            threatattr("threat"),
                            falseposattr("falsepos"),
                            sourceattr("source"),
                            destattr("dest"),
                            directionattr("direction"),
                            valueattr("value"),
                            codeattr("code"),
                            classattr("class"),
                            langattr("lang"),
                            protocolattr("protocol") {
//                            porthash(6007) {
    xmllocator = 0;
//    currententry = 0;
//    currentnetuse = 0;
//    currentnetusedetail = 0;

#ifndef QT_LITE
//    progressdialog = 0;    
#endif
//    db.setAutoDelete(true);
//    porthash.setAutoDelete(true);
    std::vector< std::string > languages;
    languages.push_back( "english" );
    loadDB( filename, languages );
}

///////////////////////////////////////////////////////////////////////////
ProtocolDB() {
//    delete currententry;    // Just a litte bit of clean up.
//    delete currentnetuse;
//    delete currentnetusedetail;
}

///////////////////////////////////////////////////////////////////////////
bool loadDB(const std::string &filename, std::vector< std::string > const & languages) {
    bool rc;
//    currententry = 0;
    parsestate = PROTOCOL_STATE_OUTSIDE;
    errorstate = PROTOCOL_ERROR_NOERROR;
    unknowndepth = 0;
    
    // Copy the list of permitted languages one by one. Convert things
    // like 'en_GB' to just 'en'.
    BOOST_FOREACH( std::string const & l, languages )
    {
        languagelist.push_back( l.substr(0,2) );
//    for(QStringList::ConstIterator lang = languages.begin(); lang != languages.end(); ++lang) {
//        languagelist.push_back((*lang).left(2));
    }
        
    QFile xmlfile( filename.c_str() );
    if(!xmlfile.open(QIODevice::ReadOnly)) {
        errorstate = PROTOCOL_ERROR_OPEN_ERROR;
        return false;
    }
//    xmlfile.close();
#ifndef QT_LITE    
//    progressdialog = new QProgressDialog(0,0,true);
//    progressdialog->setLabelText(QObject::tr("Reading network protocol database"));
#endif    
    QXmlInputSource source(&xmlfile);
    QXmlSimpleReader reader;
    reader.setContentHandler(this);
    reader.setErrorHandler(this);
    parseerror.clear(); //.truncate(0);
    if(reader.parse(source)) {
        buildPortHash();
        rc = true;
        goto cleanup;
    } else {
        rc = false;
        goto cleanup;
    }
    
cleanup:
    xmlfile.close();
#ifndef QT_LITE    
//    delete progressdialog;
//    progressdialog = 0;
#endif    
    xmllocator = 0;
    return rc;
}

///////////////////////////////////////////////////////////////////////////
bool startElement(const std::string &/*namespaceURI*/, const std::string &localName,
        const std::string &/*qName*/, const QXmlAttributes &atts) {
    int i;
    std::string protocolname;
    std::string tmp;
    bool ok;
    int x;
    
    if(unknowndepth==0) {
        switch(parsestate) {
            case PROTOCOL_STATE_OUTSIDE:
                if(localName=="protocoldb") {
                    parsestate = PROTOCOL_STATE_PROTOCOLDB;
                    i = atts.index(protocolnamespace.c_str(),linesattr.c_str());
                    if(i!=-1) {
                        numberoflines = atts.value(i).toInt(&ok);
                        if(ok==false) {
                            numberoflines = 1;
                        } else {
#ifndef QT_LITE                                
                                // Set the number of steps for the progress dialog.
//                            progressdialog->setTotalSteps(numberoflines/100);
#endif                        
                        }
                    }
                    return true;
                }
                break;

            case PROTOCOL_STATE_PROTOCOLDB:
                if(localName=="protocol") {
                    if(xmllocator!=0) {
                        if(xmllocator->lineNumber()%100==0) {
#ifndef QT_LITE
//                            progressdialog->setProgress(xmllocator->lineNumber()/100);
//                            kapp->processEvents();
#endif
                        }
                    }
                    currententry = ProtocolEntry();
                        // Fetch the name attribute.
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i==-1) {
                        errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND;
                        return false;
                    }
                    currententry.name = atts.value(i).toStdString();
                    parsestate = PROTOCOL_STATE_ENTRY;
                    return true;
                }
                break;

            case PROTOCOL_STATE_ENTRY:
                if(localName=="longname") {
                    loadlongname = false;
                    i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                    } else {
                        tmp = "en";
                    }
                    if(currententry.longnamelanguage.empty()) {
                        loadlongname = true;
                        currententry.longnamelanguage = tmp;
                    } else {
                            // Which language is more important?
                            // (Which appears first in the list of acceptable
                            // languages.)
//                        i = languagelist.indexOf(currententry.longnamelanguage);
//                        i = i==-1 ? 10000 : i;
//                        j = languagelist.indexOf(tmp);
//                        j = j==-1 ? 10000 : j;
//                        if(j<i) {
//                            loadlongname = true;
//                            currententry.longnamelanguage = tmp;
//                        }
                    }
                
                    parsestate = PROTOCOL_STATE_LONGNAME;
                    return true;
                }
                if(localName=="description") {
                    loaddescription = false;
                    i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                    } else {
                        tmp = "en";
                    }
                    if(currententry.descriptionlanguage.empty()) {
                        loaddescription = true;
                        currententry.descriptionlanguage = tmp;
                    } else {
                            // Which language is more important?
                            // (Which appears first in the list of acceptable
                            // languages.)
//                        i = languagelist.indexOf(currententry.descriptionlanguage);
//                        i = i==-1 ? 10000 : i;
//                        j = languagelist.indexOf(tmp);
//                        j = j==-1 ? 10000 : j;
//                        if(j<i) {
//                            loaddescription = true;
//                            currententry.descriptionlanguage = tmp;
//                        }
                    }
                    parsestate = PROTOCOL_STATE_DESCRIPTION;
                    return true;
                }
                if(localName=="classification") {
                    i = atts.index(protocolnamespace.c_str(),classattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="unknown") {
                            currententry.classification = CLASS_UNKNOWN;
                        } else if(tmp=="mail") {
                            currententry.classification = CLASS_MAIL;
                        } else if(tmp=="chat") {
                            currententry.classification = CLASS_CHAT;
                        } else if(tmp=="file") {
                            currententry.classification = CLASS_FILE;
                        } else if(tmp=="game") {
                            currententry.classification = CLASS_GAME;
                        } else if(tmp=="session") {
                            currententry.classification = CLASS_SESSION;
                        } else if(tmp=="data") {
                            currententry.classification = CLASS_DATA;
                        } else if(tmp=="media") {
                            currententry.classification = CLASS_MEDIA;
                        } else if(tmp=="net") {
                            currententry.classification = CLASS_NET;
                        } else {
                            errorstate = PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_CLASSIFICATION;
                    return true;
                }
                if(localName=="network") {
                    parsestate = PROTOCOL_STATE_NETWORK;
                    return true;
                }
                if(localName=="security") {
                        // Grab the threat info
                    i = atts.index(protocolnamespace.c_str(),threatattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="unknown") {
                            currententry.threat = SCORE_UNKNOWN;
                        } else if(tmp=="low") {
                            currententry.threat = SCORE_LOW;
                        } else if(tmp=="medium") {
                            currententry.threat = SCORE_MEDIUM;
                        } else if(tmp=="high") {   
                            currententry.threat = SCORE_HIGH;
                        } else {
                            errorstate = PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN;
                            return false;
                        }
                    }

                        // Grab the falsepos info
                    i = atts.index(protocolnamespace.c_str(),falseposattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="unknown") {
                            currententry.falsepos = SCORE_UNKNOWN;
                        } else if(tmp=="low") {
                            currententry.falsepos = SCORE_LOW;
                        } else if(tmp=="medium") {
                            currententry.falsepos = SCORE_MEDIUM;
                        } else if(tmp=="high") {
                            currententry.falsepos = SCORE_HIGH;
                        } else {
                            errorstate = PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_SECURITY;
                    return true;
                }

                if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currententry.pragmaname.push_back(tmp);
                    } else {
                        currententry.pragmaname.push_back(std::string());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
                    return true;
                }
                break;

            case PROTOCOL_STATE_NETWORK:
                if(localName=="tcp") {
                    currentnetuse = ProtocolNetUse();
                    currentnetuse.type = IPPROTO_TCP;
                        // Handle Source attribute
                    i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.source = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.source = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN;
                            return false;
                        }
                    }
                        // Handle Dest attribute
                    i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.dest = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.dest = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_TCP_DEST_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_TCP;
                    return true;
                }
                if(localName=="udp") {
                    currentnetuse = ProtocolNetUse();
                    currentnetuse.type = IPPROTO_UDP;
                        // Handle Source attribute
                    i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.source = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.source = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN;
                            return false;
                        }
                    }
                        // Handle Dest attribute
                    i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.dest = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.dest = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_UDP_DEST_UNKNOWN;
                            return false;
                        }
                    }
                    
                        // Check for direction attribute
                    i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                    if(i!=-1) {
                        currentnetuse.bidirectional = true;
                    }
                    parsestate = PROTOCOL_STATE_UDP;
                    return true;
                }
                if(localName=="icmp") {
                    currentnetuse = ProtocolNetUse();
                    currentnetuse.type = IPPROTO_ICMP;
                        // Handle Source attribute
                    i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.source = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.source = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN;
                            return false;
                        }
                    }
                        // Handle Dest attribute
                    i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.dest = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.dest = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_ICMP_DEST_UNKNOWN;
                            return false;
                        }
                    }
                    parsestate = PROTOCOL_STATE_ICMP;
                    return true;
                }
                if(localName=="ip") {
                    currentnetuse = ProtocolNetUse();
                    currentnetuse.type = 0;    // Dummy.
                        
                        // Handle the Protocol attribute.
                    i = atts.index(protocolnamespace.c_str(),protocolattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        try {
                            ok = true;
                            x = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                        }
                        catch ( ... )
                        {
                            ok = false;
                        }
                        if(ok==false) {
                            errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT;
                            return false;
                        }
                        if(x<0 || x>255) {
                            errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE;
                            return false;
                        }
                        currentnetuse.type = x;
                    } else {
                        errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                        return false;
                    }
                        // Handle Source attribute
                    i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.source = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.source = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_IP_SOURCE_UNKNOWN;
                            return false;
                        }
                    }
                        // Handle Dest attribute
                    i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        if(tmp=="client") {
                            currentnetuse.dest = ENTITY_CLIENT;
                        } else if(tmp=="server") {
                            currentnetuse.dest = ENTITY_SERVER;
                        } else {
                            errorstate = PROTOCOL_ERROR_IP_DEST_UNKNOWN;
                            return false;
                        }
                    }
                    
                        // Check for direction attribute
                    i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                    if(i!=-1) {
                        currentnetuse.bidirectional = true;
                    }
                    parsestate = PROTOCOL_STATE_IP;
                    return true;
                }

                break;

            case PROTOCOL_STATE_TCP:
                if(localName=="source") {
                    parsestate = PROTOCOL_STATE_TCP_SOURCE;
                    return true;
                }
                if(localName=="dest") {
                    parsestate = PROTOCOL_STATE_TCP_DEST;
                    return true;
                }
                if(localName=="description") {
                    doNetuseLanguage(atts);
                    parsestate = PROTOCOL_STATE_TCP_DESCRIPTION;
                    return true;
                }
                if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currentnetuse.pragmaname.push_back(tmp);
                    } else {
                        currentnetuse.pragmaname.push_back(std::string());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_TCP_PRAGMA;
                    return true;
                }
                break;
                
            case PROTOCOL_STATE_UDP:
                if(localName=="source") {
                    parsestate = PROTOCOL_STATE_UDP_SOURCE;
                    return true;
                }
                if(localName=="dest") {
                    parsestate = PROTOCOL_STATE_UDP_DEST;
                    return true;
                }
                if(localName=="description") {
                    doNetuseLanguage(atts);
                    parsestate = PROTOCOL_STATE_UDP_DESCRIPTION;
                    return true;
                }
                if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currentnetuse.pragmaname.push_back(tmp);
                    } else {
                        currentnetuse.pragmaname.push_back(std::string());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_UDP_PRAGMA;
                    return true;
                }
                break;
                
            case PROTOCOL_STATE_ICMP:
                if(localName=="type") {
                    currentnetusedetail = ProtocolNetUseDetail();
                     currentnetusedetail.alternate = false;
                     currentnetusedetail.rangetype = PORTRANGE_RANGE;
                     currentnetusedetail.code = -1;
                        // Grab the type number
                    i = atts.index(protocolnamespace.c_str(),valueattr.c_str());
                    if(i==-1) {
                        errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i).toStdString();
                    currentnetusedetail.type = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                    if(ok==false) {
                        errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT;
                        return false;
                    }
                
                        // Grab the ICMP code.
                    i = atts.index(protocolnamespace.c_str(),codeattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.code = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                        if(ok==false) {
                            errorstate = PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT;
                            return false;
                        }
                    }
                
                    parsestate = PROTOCOL_STATE_ICMP_TYPE;
                    return true;
                }
                if(localName=="description") {
                    doNetuseLanguage(atts);
                    parsestate = PROTOCOL_STATE_ICMP_DESCRIPTION;
                    return true;
                }
                if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currentnetuse.pragmaname.push_back(tmp);
                    } else {
                        currentnetuse.pragmaname.push_back(std::string());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_ICMP_PRAGMA;
                    return true;
                }
                break;
                
            case PROTOCOL_STATE_IP:
                if(localName=="description") {
                    doNetuseLanguage(atts);
                    parsestate = PROTOCOL_STATE_IP_DESCRIPTION;
                    return true;
                }
                if(localName=="pragma") {
                        // Grab the pragma name
                    i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                    if(i!=-1) {
                        tmp = atts.value(i).toStdString();
                        currentnetuse.pragmaname.push_back(tmp);
                    } else {
                        currentnetuse.pragmaname.push_back(std::string());  // Null string.
                    }
                    parsestate = PROTOCOL_STATE_IP_PRAGMA;
                    return true;
                }
                break;
                
            case PROTOCOL_STATE_TCP_SOURCE:
            case PROTOCOL_STATE_UDP_SOURCE:
            case PROTOCOL_STATE_TCP_DEST:
            case PROTOCOL_STATE_UDP_DEST:
                if(localName=="port") {
                    currentnetusedetail = ProtocolNetUseDetail();
                    currentnetusedetail.rangetype = PORTRANGE_RANGE;
                     currentnetusedetail.alternate = false;
                    currentnetusedetail.start = 0;
                    currentnetusedetail.end = 0;
                        
                        // Grab the port number
                    i = atts.index(protocolnamespace.c_str(),portnumattr.c_str());
                    if(i==-1) {
                        errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i).toStdString();
                               
                    if(tmp=="any") {
                        currentnetusedetail.rangetype = PORTRANGE_ANY;
                        currentnetusedetail.start = 0;
                        currentnetusedetail.end = 65535;
                    } else if(tmp=="privileged") {
                        currentnetusedetail.rangetype = PORTRANGE_PRIVILEGED;
                        currentnetusedetail.start = 0;
                        currentnetusedetail.end = 1023;
                    } else if(tmp=="nonprivileged") {
                        currentnetusedetail.rangetype = PORTRANGE_NONPRIVILEGED;
                        currentnetusedetail.start = 1024;
                        currentnetusedetail.end = 65535;
                    } else if(tmp=="dynamic") {
                        currentnetusedetail.rangetype = PORTRANGE_DYNAMIC;
                        currentnetusedetail.start = 1024;
                        currentnetusedetail.end = 65535;
                    } else { 
                        currentnetusedetail.start = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                        if(ok==false) {
                            errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT;
                            return false;
                        }
                        currentnetusedetail.end = currentnetusedetail.start;
                    }
                        // Should check for the alternative flag around here somewhere.
                    
                    switch(parsestate) {
                        case PROTOCOL_STATE_TCP_SOURCE:
                            parsestate = PROTOCOL_STATE_TCP_SOURCE_PORT;
                            break;
                        case PROTOCOL_STATE_UDP_SOURCE:
                            parsestate = PROTOCOL_STATE_UDP_SOURCE_PORT;
                            break;
                        case PROTOCOL_STATE_TCP_DEST:
                            parsestate = PROTOCOL_STATE_TCP_DEST_PORT;
                            break;
                            
                        case PROTOCOL_STATE_UDP_DEST:
                            parsestate = PROTOCOL_STATE_UDP_DEST_PORT;
                            break;
                        default:
                            break;
                     }
                    return true;
                }
                if(localName=="portrange") {
                    currentnetusedetail = ProtocolNetUseDetail();
                    currentnetusedetail.rangetype = PORTRANGE_RANGE;
                    currentnetusedetail.alternate = false;
                        // Grab the start port number
                    i = atts.index(protocolnamespace.c_str(),portstartattr.c_str());
                    if(i==-1) {
                        errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i).toStdString();
                    currentnetusedetail.start = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                    if(ok==false) {
                        errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT;
                        return false;
                    }

                        // Grab the end port number
                    i = atts.index(protocolnamespace.c_str(),portendattr.c_str());
                    if(i==-1) {
                        errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND;
                        return false;
                    }
                    tmp = atts.value(i).toStdString();
                    currentnetusedetail.end = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                    if(ok==false) {
                        errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT;
                        return false;
                    }
                    if(currentnetusedetail.end < currentnetusedetail.start) {
                        errorstate = PROTOCOL_ERROR_PORTRANGE_END_LESS_START;
                        return false;
                    }
                    
                    switch(parsestate) {
                        case PROTOCOL_STATE_TCP_SOURCE:
                            parsestate = PROTOCOL_STATE_TCP_SOURCE_PORTRANGE;
                            break;
                        case PROTOCOL_STATE_UDP_SOURCE:
                            parsestate = PROTOCOL_STATE_UDP_SOURCE_PORTRANGE;
                            break;
                        case PROTOCOL_STATE_TCP_DEST:
                            parsestate = PROTOCOL_STATE_TCP_DEST_PORTRANGE;
                            break;
                            
                        case PROTOCOL_STATE_UDP_DEST:
                            parsestate = PROTOCOL_STATE_UDP_DEST_PORTRANGE;
                            break;
                        default:
                            break;
                     }
                    return true;
                }
                break;

            default:
                break;
        }
    }
    unknowndepth++;
    return true;
}
    
///////////////////////////////////////////////////////////////////////////
void doNetuseLanguage(const QXmlAttributes &atts) {
    int i;                    
    std::string tmp;
    
    loaddescription = false;
    i = atts.index(protocolnamespace.c_str(),langattr.c_str());
    if(i!=-1) {
        tmp = atts.value(i).toStdString();
    } else {
        tmp = "en";
    }
    if(currentnetuse.descriptionlanguage.empty()) {
        loaddescription = true;
        currentnetuse.descriptionlanguage = tmp;
    } else {
            // Which language is more important?
            // (Which appears first in the list of acceptable
            // languages.)
//        i = languagelist.indexOf(currentnetuse.descriptionlanguage);
//        i = i==-1 ? 10000 : i;
//        j = languagelist.indexOf(tmp);
//        j = j==-1 ? 10000 : j;
//        if(j<i) {
//            loaddescription = true;
//            currentnetuse.descriptionlanguage = tmp;
//        }
    }
}

///////////////////////////////////////////////////////////////////////////
bool endElement(const std::string &/*namespaceURI*/, const std::string &/*localName*/,
        const std::string &/*qName*/) {

    if(unknowndepth==0) {
        switch(parsestate) {
            case PROTOCOL_STATE_PROTOCOLDB:
                parsestate = PROTOCOL_STATE_FINISHED;
                return true;

            case PROTOCOL_STATE_ENTRY:
                    // We are just exiting an entry.
                db.push_back(currententry); // Add it to the end of our list.
//                currententry = 0;
                parsestate = PROTOCOL_STATE_PROTOCOLDB;
                return true;

            case PROTOCOL_STATE_LONGNAME:
            case PROTOCOL_STATE_DESCRIPTION:
            case PROTOCOL_STATE_SECURITY:
            case PROTOCOL_STATE_NETWORK:
            case PROTOCOL_STATE_CLASSIFICATION:
            case PROTOCOL_STATE_ENTRY_PRAGMA:
                parsestate = PROTOCOL_STATE_ENTRY;
                return true;
                
            case PROTOCOL_STATE_TCP:
            case PROTOCOL_STATE_UDP:
                    // If no port info was given for the source ports or dest ports,
                    // then we assume that they mean any port. So we just add an any
                    // port range entry to the list.
                if(currentnetuse.sourcedetaillist.count()==0) {
                    currentnetusedetail = ProtocolNetUseDetail();
                    currentnetusedetail.rangetype = PORTRANGE_ANY;
                     currentnetusedetail.alternate = false;
                    currentnetusedetail.start = 0;
                    currentnetusedetail.end = 65535;
                    currentnetuse.sourcedetaillist.push_back(currentnetusedetail);
//                    currentnetusedetail = 0;
                }
                if(currentnetuse.destdetaillist.count()==0) {
                    currentnetusedetail = ProtocolNetUseDetail();
                    currentnetusedetail.rangetype = PORTRANGE_ANY;
                     currentnetusedetail.alternate = false;
                    currentnetusedetail.start = 0;
                    currentnetusedetail.end = 65535;
                    currentnetuse.destdetaillist.push_back(currentnetusedetail);
//                    currentnetusedetail = 0;
                }
                    // This fall through is intentional.
            case PROTOCOL_STATE_ICMP:
            case PROTOCOL_STATE_IP:
                currententry.networkuse.push_back(currentnetuse);
//                currentnetuse = 0;
                parsestate = PROTOCOL_STATE_NETWORK;
                return true;

            case PROTOCOL_STATE_TCP_SOURCE:
            case PROTOCOL_STATE_TCP_DEST:
            case PROTOCOL_STATE_TCP_DESCRIPTION:
            case PROTOCOL_STATE_TCP_PRAGMA:
                parsestate = PROTOCOL_STATE_TCP;
                return true;
            
            case PROTOCOL_STATE_UDP_SOURCE:
            case PROTOCOL_STATE_UDP_DEST:
            case PROTOCOL_STATE_UDP_DESCRIPTION:
            case PROTOCOL_STATE_UDP_PRAGMA:
                parsestate = PROTOCOL_STATE_UDP;
                return true;

            case PROTOCOL_STATE_ICMP_TYPE:
                currentnetuse.sourcedetaillist.push_back(currentnetusedetail);
                parsestate = PROTOCOL_STATE_ICMP;
                return true;
            
            case PROTOCOL_STATE_ICMP_DESCRIPTION:
            case PROTOCOL_STATE_ICMP_PRAGMA:
                parsestate = PROTOCOL_STATE_ICMP;
                return true;
            
            case PROTOCOL_STATE_IP_DESCRIPTION:
            case PROTOCOL_STATE_IP_PRAGMA:
                parsestate = PROTOCOL_STATE_IP;
                return true;

            case PROTOCOL_STATE_TCP_SOURCE_PORT:
            case PROTOCOL_STATE_TCP_SOURCE_PORTRANGE:
                currentnetuse.sourcedetaillist.push_back(currentnetusedetail);
//                currentnetusedetail = 0;
                parsestate = PROTOCOL_STATE_TCP_SOURCE;
                return true;
            
            case PROTOCOL_STATE_TCP_DEST_PORT:
            case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
                currentnetuse.destdetaillist.push_back(currentnetusedetail);
//                currentnetusedetail = 0;
                parsestate = PROTOCOL_STATE_TCP_DEST;
                return true;
                
            case PROTOCOL_STATE_UDP_SOURCE_PORT:
            case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
                currentnetuse.sourcedetaillist.push_back(currentnetusedetail);
//                currentnetusedetail = 0;
                parsestate = PROTOCOL_STATE_UDP_SOURCE;
                return true;

            case PROTOCOL_STATE_UDP_DEST_PORT:
            case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
                currentnetuse.destdetaillist.push_back(currentnetusedetail);
//                currentnetusedetail = 0;
                parsestate = PROTOCOL_STATE_UDP_DEST;
                return true;
                                
            default:
                return false;
        }
    }
    unknowndepth--;
    return true;
}

///////////////////////////////////////////////////////////////////////////
bool characters(const std::string &ch) {
    if(unknowndepth) {
        return true;
    }

    switch(parsestate) {
        case PROTOCOL_STATE_LONGNAME:
            if(loadlongname) {
                currententry.longname = ch;
            }
            return true;

        case PROTOCOL_STATE_DESCRIPTION:
            if(loaddescription) {
                currententry.description = ch;
            }
            return true;

        case PROTOCOL_STATE_ENTRY_PRAGMA:
            currententry.pragmavalue.push_back(ch);
            return true;
                    
        case PROTOCOL_STATE_TCP_DESCRIPTION:
        case PROTOCOL_STATE_UDP_DESCRIPTION:
        case PROTOCOL_STATE_ICMP_DESCRIPTION:
            if(loaddescription) {
                currentnetuse.description = ch;
            }
            return true;

        case PROTOCOL_STATE_TCP_PRAGMA:
        case PROTOCOL_STATE_UDP_PRAGMA:
        case PROTOCOL_STATE_ICMP_PRAGMA:
            currentnetuse.pragmavalue.push_back(ch);
            return true;    
            
        default:
            break;
    }
    return true;
}

///////////////////////////////////////////////////////////////////////////
void setDocumentLocator(QXmlLocator *l) {
    xmllocator = l;
}

///////////////////////////////////////////////////////////////////////////
bool error(const QXmlParseException &exception) {
    printParseException(exception);
    errorstate = PROTOCOL_ERROR_PARSE_ERROR;
    return false;
}

///////////////////////////////////////////////////////////////////////////
bool fatalError(const QXmlParseException &exception) {
    printParseException(exception);
    errorstate = PROTOCOL_ERROR_PARSE_ERROR;
    return false;
}

///////////////////////////////////////////////////////////////////////////
bool warning(const QXmlParseException &exception) {
    printParseException(exception);
    errorstate = PROTOCOL_ERROR_PARSE_ERROR;
    return false;
}

///////////////////////////////////////////////////////////////////////////
std::string errorString() {
    switch(errorstate) {
        case PROTOCOL_ERROR_NOERROR:
            return ("No error (You should not see this).");
        case PROTOCOL_ERROR_OPEN_ERROR:
            return ("Unable to open the network protocol database XML file.");
        case PROTOCOL_ERROR_PARSE_ERROR:
        {
            std::string message( "XML Parse error:\n");
            BOOST_FOREACH( std::string const & s, parseerror )
            {
                message += s;
            }
            return message;
        }
        case PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND:
            return ("'protocol' tag requires a 'name' attribute, but none was found.");
        case PROTOCOL_ERROR_SECURITY_LEVEL_UNKNOWN:
            return ("'threat' attribute has an unrecognised value.");
        case PROTOCOL_ERROR_SECURITY_FALSEPOS_UNKNOWN:
            return ("'falsepos' attribute has an unrecognised value.");
        case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND:
            return ("'port' element requires a 'portnum' attribute, but none was found.");
        case PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT:
            return ("'portnum' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND:
            return ("'portrange' element requires a 'start' attribute, but none was found.");
        case PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT:
            return ("'start' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND:
            return ("'portrange' element requires a 'end' attribute, but none was found.");
        case PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT:
            return ("'end' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_PORTRANGE_END_LESS_START:
            return ("'start' attribute must be greater than 'end' attribute.");
        case PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN:
        case PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN:
        case PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN:
        case PROTOCOL_ERROR_IP_SOURCE_UNKNOWN:
            return ("'source' attribute must be one of 'client', 'server' or 'host'.");
        case PROTOCOL_ERROR_TCP_DEST_UNKNOWN:
        case PROTOCOL_ERROR_UDP_DEST_UNKNOWN:
        case PROTOCOL_ERROR_ICMP_DEST_UNKNOWN:
        case PROTOCOL_ERROR_IP_DEST_UNKNOWN:
            return ("'dest' attribute must be one of 'client', 'server' or 'host'.");
        case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND:
            return ("'type' element requires a 'value' attribute, but none was found.");
        case PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT:
            return ("'value' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT:
            return ("'code' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_CLASSIFICATION_CLASS_UNKNOWN:
            return ("'class' attribute has an unrecognised value.");
        case PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND:
            return ("'ip' element requires a 'protocol' attribute, but none was found.");
        case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT:
               return ("'protocol' attribute is not a valid unsigned integer.");
        case PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE:
            return ("'protocol' attribute is out of range. (Must be 8 bit).");

        default:
            return ("Unknown error. (You should never see this).");
    }
}

///////////////////////////////////////////////////////////////////////////
void printParseException(const QXmlParseException &exception) {
    std::stringstream ss;
    ss << "Line: " << exception.lineNumber() << ", "
       << "Column: " << exception.columnNumber() << " " << exception.systemId().toStdString() << ", "
       << exception.publicId().toStdString() << ", " << exception.message().toStdString() << std::endl;
    parseerror.push_back( ss.str() );
}

///////////////////////////////////////////////////////////////////////////
// We have a hash mapping port numbers to related entries in the protocol
// database.
//
void buildPortHash() {

//    for(entry=db.first(); entry!=0; entry=db.next()) {
    BOOST_FOREACH( ProtocolEntry const & entry, db ) {
        addEntryToPortHash(entry);
    }
}

///////////////////////////////////////////////////////////////////////////
void addEntryToPortHash(ProtocolEntry const & entry) {
    uint i;

    BOOST_FOREACH( ProtocolNetUse const & netuse, entry.networkuse ) {
//    for(netuse=entry->networkuse.first(); netuse!=0; netuse=entry->networkuse.next()) {
                
        BOOST_FOREACH( ProtocolNetUseDetail const & detail, netuse.sourcedetaillist ) {
//        for(detail=netuse->sourcedetaillist.first(); detail!=0; detail=netuse->sourcedetaillist.next()) {
            if(detail.rangetype==PORTRANGE_RANGE) {  // We only do normal ranges.
                if(netuse.type==IPPROTO_ICMP) {
                    addEntryToHash(entry,netuse.type,detail.type);
                } else {
                    for(i=detail.start; i<=detail.end; i++) {
                        addEntryToHash(entry,netuse.type,i);
                    }
                }
            }
        }
                
        BOOST_FOREACH( ProtocolNetUseDetail const & detail, netuse.destdetaillist ) {
//        for(detail=netuse->destdetaillist.first(); detail!=0; detail=netuse->destdetaillist.next()) {
            if(detail.rangetype==PORTRANGE_RANGE) {  // We only do normal ranges.
                if(netuse.type==IPPROTO_ICMP) {
                    addEntryToHash(entry,netuse.type,detail.type);
                } else {
                    for(i=detail.start; i<=detail.end; i++) {
                        addEntryToHash(entry,netuse.type,i);
                    }
                }
            }                
        }
    }
}

///////////////////////////////////////////////////////////////////////////
long hashKey(uchar type, uint port) {
    return (long)((((uint)type)<<24)|port);
}

///////////////////////////////////////////////////////////////////////////
void addEntryToHash(ProtocolEntry const & entry, uchar type, uint port) {
#if 0
    QList<ProtocolEntry *> bucket;
    long key;

    key = hashKey(type,port);
    bucket = porthash.find(key);
    if(bucket==0) {
        bucket = new QList<ProtocolEntry>;
        porthash.insert(key,bucket);
    }
    bucket->push_back(entry);
#endif
}

///////////////////////////////////////////////////////////////////////////
void removeEntryFromPortHash(ProtocolEntry const & entry) {
#if 0
    QIntDictIterator< QList<ProtocolEntry> > it(porthash);
    QList<ProtocolEntry> *bucket;
        
        // Search through the whole port hash removing any references to
        // the entry.
    while(it.current()) {
        bucket = it.current();
        bucket->removeRef(entry);
        ++it;
    }
#endif
}

///////////////////////////////////////////////////////////////////////////
//QList<ProtocolEntry *>::iterator lookup(uchar type, uint port) {
//    return porthash.find(hashKey(type,port));
//}

///////////////////////////////////////////////////////////////////////////

//#include <boost/spirit/home/phoenix/bind.hpp>
//#include <boost/spirit/home/phoenix/core/argument.hpp>

struct X
{
    std::string const & name;
    X( std::string const & _n ) : name( _n ) { }

    bool operator()( ProtocolEntry const & pe ) const
    {
        return pe.name == name;
    }
};

std::vector< ProtocolEntry >::const_iterator lookup(std::string const & name) 
{
std::cout << "Looking up protocol " << name << std::endl;
    X x(name );
    return std::find_if( db.begin(), db.end(), x );
//    QListIterator<ProtocolEntry> *dbit;
//    ProtocolEntry *proto;
//    
//    dbit = db.begin();   // Yes, linear search.
//    for(;dbit->current(); ++(*dbit)) {
//        if(dbit->current()->name==name) {
//            proto = dbit->current();
//            delete dbit;
//            return proto;
//        }    
//    }
//    delete dbit;
//    return 0;
}
    
///////////////////////////////////////////////////////////////////////////
//QListIterator<ProtocolEntry> *newDatabaseIterator() {
//    return new QListIterator<ProtocolEntry>(db);
//}

///////////////////////////////////////////////////////////////////////////
void insertEntry(ProtocolEntry const & entry) {
    db.push_back(entry);
    addEntryToPortHash(entry);
}
///////////////////////////////////////////////////////////////////////////
bool takeEntry(ProtocolEntry const & entry) {
#if 0
//    db.setAutoDelete(false);    // Just temp.
    if(!db.removeRef(entry)) {
//        db.setAutoDelete(true);
        return false;
    }
//    db.setAutoDelete(true);
    removeEntryFromPortHash(entry);
#endif
    return true;
}

///////////////////////////////////////////////////////////////////////////
bool removeEntry(ProtocolEntry const & entry) {
    if(takeEntry(entry)) {
//        delete entry;
        return true;
    } else {
        return false;
    }
}

};

#endif
