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
#pragma once

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>


#include <QXmlDefaultHandler>

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

// Just a tiny helper class.
// Holds a single port range.
struct PortRangeInfo
{
    uint dynamicStart;
    uint dynamicEnd;

    PortRangeInfo(uint s = 1024, uint e = 65535 )
        : dynamicStart( s ), dynamicEnd( e )
    {
    }
};

enum RangeType
{
    PORTRANGE_RANGE=0,
    PORTRANGE_ANY,
    PORTRANGE_PRIVILEGED,
    PORTRANGE_NONPRIVILEGED,
    PORTRANGE_DYNAMIC
};
enum NetworkEntity
{
    ENTITY_SERVER,
    ENTITY_CLIENT
};
enum Classification
{
    CLASS_UNKNOWN=0,
    CLASS_MAIL,
    CLASS_CHAT,
    CLASS_FILE,
    CLASS_GAME,
    CLASS_SESSION,
    CLASS_DATA,
    CLASS_MEDIA,
    CLASS_NET,
    CLASS_CUSTOM
};


class ProtocolNetUseDetail
{

    bool alternate;
    RangeType rangetype;
    union
    {
        uint start; // tcmp, udp
        uint type;  // icmp
    };
    union
    {
        uint end;   // tcp, udp
        int code;   // icmp
    };
public:

    bool operator==(ProtocolNetUseDetail const & that) const
    {
        return  alternate       ==  that.alternate
                && rangetype    ==  that.rangetype
                && start        ==  that.start
                && end          ==  that.end;
    }

    ProtocolNetUseDetail() {
        alternate = false;
        rangetype = PORTRANGE_RANGE;
        start = 0;
        end = 0;
    }

    ProtocolNetUseDetail( bool _alternate, RangeType const & _rangetype, uint _start, uint _end )
     : alternate( _alternate ), rangetype( _rangetype ), start( _start ), end( _end )
    {
    }

    std::string getRangeString() const
    {
        std::stringstream result;
        if (start == end)
            result << start;
        else
            result << start << ":" << end;
        return result.str();
    }

    void setStartPort(uint p)
    {
        start = p;
        if(start > end) {
            end = p;
        }
    }

    void setEndPort(uint p)
    {
        end = p;
        if ( start > end)
        {
            start = p;
        }
    }


    ///////////////////////////////////////////////////////////////////////////
    ~ProtocolNetUseDetail()
    {

    }
    bool inRange( uint port ) const
    {
        return port >= start && port <= end;
    }

    void setAlternate( bool a ) { alternate = a; }
    void setRangeType( RangeType const & r ) { rangetype = r; }
    void setCode( int c ) { code = c; }
    void setStart( uint c ) { start = c; }
    void setEnd( uint c ) { end = c; }
    void setType( uint c ) { type = c; }

    uint getStart( ) const { return start; }
    uint getEnd( ) const { return end; }

    uint getType() const { return type; }
    int getCode() const { return code; }

    ///////////////////////////////////////////////////////////////////////////
    uint getStart(PortRangeInfo const * ri ) const
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
    uint getEnd(const PortRangeInfo *ri ) const
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

class ProtocolNetUse
{
    //        bool sourcePortEquals(uint port);
    //        bool destPortEquals(uint port);
    //       bool icmpTypeCodeEquals(uint type, int code);
public:
    std::string   descriptionlanguage;
    std::string   description;
    uchar         type;    // IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP
    bool          bidirectional;    // For UDP.
    NetworkEntity source;
    NetworkEntity dest;

    uchar         getType() const { return type; }   // IPPROTO_TCP, IPPROTO_UDP or IPPROTO_ICMP

private:
    std::vector<ProtocolNetUseDetail> sourcedetaillist;     // A list of source port ranges.
    std::vector<ProtocolNetUseDetail> destdetaillist;       // A list of dest port ranges.

public:
    std::string lastPragmaName;
    std::map< std::string, std::string > pragma;

    bool operator==(ProtocolNetUse const & that) const
    {
        return  descriptionlanguage     ==  that.descriptionlanguage
                &&  description         ==  that.description
                &&  type                ==  that.type
                &&  bidirectional       ==  that.bidirectional
                &&  source              ==  that.source
                &&  dest                ==  that.dest
                &&  sourcedetaillist    ==  that.sourcedetaillist
                &&  destdetaillist      ==  that.destdetaillist
                &&  lastPragmaName      ==  that.lastPragmaName
                &&  pragma              ==  that.pragma;
    }

    void addPragmaValue( std::string const & value )
    {
        std::cout << "Pragma " << lastPragmaName << " = " << value << std::endl;
        pragma[ lastPragmaName ] = value;
    }


    std::vector<ProtocolNetUseDetail> const & sourceDetails() const
    {
        return sourcedetaillist;
    }
    std::vector<ProtocolNetUseDetail> const & destDetails() const
    {
        return destdetaillist;
    }

    size_t numberSourcePorts() const { return sourcedetaillist.size(); }
    size_t numberDestPorts() const { return destdetaillist.size(); }

    void setType( uchar t ) { type = t; }
    void setSource( NetworkEntity s ) { source = s; }
    void setDest( NetworkEntity d ) { dest = d; }
    void setBidirectional( bool b ) { bidirectional = b; }

    void addSource( ProtocolNetUseDetail const & source )
    {
        sourcedetaillist.push_back( source );
    }

    void addDest( ProtocolNetUseDetail const & dest )
    {
        destdetaillist.push_back( dest );
    }


    ProtocolNetUse()
    {
        //    sourcedetaillist.setAutoDelete(true);
        //    destdetaillist.setAutoDelete(true);
        source = ENTITY_CLIENT;
        dest = ENTITY_SERVER;
        bidirectional = false;
    }

    bool isBidirectional() const
    {
        return (type==IPPROTO_TCP) || bidirectional;
    }


    ///////////////////////////////////////////////////////////////////////////
    ~ProtocolNetUse() {

    }

    ///////////////////////////////////////////////////////////////////////////
    void print() const
    {

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
        BOOST_FOREACH( ProtocolNetUseDetail const & x, sourcedetaillist )
        {
            x.print();
        }
        fprintf(stderr," Dest: ");
        BOOST_FOREACH( ProtocolNetUseDetail const & x, destdetaillist )
        {
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
            if ( p.inRange( port ) ) //port>=p.start && port<=p.end)
            {    // It must be in range.
                return true;
            }
        }
        return false;
    }
    ///////////////////////////////////////////////////////////////////////////
    bool destPortEquals(uint port) {

        //    p=destdetaillist.first();
        if ( destdetaillist.empty() ) {
            return true;    // An empty list matches anything.
        }
        BOOST_FOREACH( ProtocolNetUseDetail const & p, destdetaillist ) {
            if(p.inRange( port ) ) { //>=p.start && port<=p.end) {
                return true;
            }
        }
        return false;
    }
    ///////////////////////////////////////////////////////////////////////////
    bool icmpTypeCodeEquals(uint type, int code)
    {
        BOOST_FOREACH( ProtocolNetUseDetail const & p, sourcedetaillist )
        {
            if ( type==p.getType() )
            {
                if (p.getCode()==-1)
                {    // -1 is the wild card.
                    return true;
                }
                else
                {
                    if(p.getCode()==code)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }


};
enum Score
{
    SCORE_UNKNOWN=0,
    SCORE_LOW,
    SCORE_MEDIUM,
    SCORE_HIGH
};

class ProtocolEntry
{
public:
    std::string name;
    std::string longnamelanguage;
    std::string longname;

    std::string descriptionlanguage;
    std::string description;

    Score threat;
    Score falsepos;
    Classification classification;

private:
    friend class ProtocolDB;
    std::vector< ProtocolNetUse > networkuse;
public:
    std::string lastPragmaName;
    std::map< std::string, std::string > pragma;

    bool operator==(ProtocolEntry const & that) const
    {
        return      name                ==  that.name
                &&  longnamelanguage    ==  that.longnamelanguage
                &&  longname            ==  that.longname
                &&  descriptionlanguage ==  that.descriptionlanguage
                &&  description         ==  that.description
                &&  threat              ==  that.threat
                &&  falsepos            ==  that.falsepos
                &&  classification      ==  that.classification
                &&  networkuse          ==  that.networkuse
                &&  lastPragmaName      ==  that.lastPragmaName
                &&  pragma              ==  that.pragma;
    }
    void addPragmaValue( std::string const & value )
    {
        std::cout << "Pragma " << lastPragmaName << " = " << value << std::endl;
        pragma[ lastPragmaName ] = value;
    }

    void addNetwork( ProtocolNetUse const & net )
    {
        networkuse.push_back( net );
    }

    void setName( std::string const & n ) { name = n; }

    ProtocolEntry( std::string const & _name = "" )
     : name( _name )
    {
        //    networkuse.setAutoDelete(true);
        threat         = SCORE_UNKNOWN;
        falsepos       = SCORE_UNKNOWN;
        classification = CLASS_UNKNOWN;
    }

    ///////////////////////////////////////////////////////////////////////////
    ~ProtocolEntry()
    {

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
            x.print();
        }
        fprintf(stderr,"]");
    }



};

class ProtocolDB : public QXmlDefaultHandler
{

public:
    std::vector< ProtocolEntry > const & getProtocolDataBase() const
    {
        return protocolDataBase;
    }

    void addProtocolEntry( ProtocolEntry const & pe )
    {
        protocolDataBase.push_back( pe );
    }

private:
    std::vector< ProtocolEntry > protocolDataBase;

//    QXmlLocator *xmllocator;
    ProtocolEntry currententry;

    ProtocolNetUse currentnetuse;
    ProtocolNetUseDetail currentnetusedetail;


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
    enum ErrorState
    {
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
public:
    ProtocolDB( std::string const & filename )
     :  protocolnamespace(""),
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
        protocolattr("protocol")
    {
        std::vector< std::string > languages;
        languages.push_back( "english" );
        loadDB( filename, languages );
    }

    ProtocolDB()
    {
    }

    std::vector< ProtocolNetUse > const & getNetworkUses( std::string const & protocolName ) const
    {
        return lookup( protocolName ).networkuse;
    }

    ///////////////////////////////////////////////////////////////////////////
    bool loadDB(const std::string &filename, std::vector< std::string > const & languages)
    {
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
        }

        /*!
        **  \todo Need to eliminate the dependence on QFile
        **       for the XML parsing.
        */
        QFile xmlfile( filename.c_str() );
        if(!xmlfile.open(QIODevice::ReadOnly)) {
            errorstate = PROTOCOL_ERROR_OPEN_ERROR;
            std::cout << "unable to open: " << filename << std::endl;
            return false;
        }
        QXmlInputSource source(&xmlfile);
        QXmlSimpleReader reader;
        reader.setContentHandler(this);
        reader.setErrorHandler(this);
        parseerror.clear(); //.truncate(0);
        std::cout << "Parsing...";
        if ( reader.parse(source))
        {
            std::cout << "success" << std::endl;
            rc = true;
            goto cleanup;
        }
        else
        {
            std::cout << "failed" << std::endl;
            std::cout << errorString().toStdString() << std::endl;
            rc = false;
            goto cleanup;
        }

cleanup:
        xmlfile.close();
        return rc;
    }

    bool startElement(const QString &/*namespaceURI*/, QString const & localName, const QString &/*qName*/, const QXmlAttributes &atts)
    {
        int i;
        std::string protocolname;
        std::string tmp;
        bool ok;
        int x;

        if(unknowndepth==0)
        {
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
                    if ( localName=="protocol" )
                    {
//                        if ( xmllocator !=0 )
//                        {
//                            if(xmllocator->lineNumber()%100==0) {
#ifndef QT_LITE
                                //                            progressdialog->setProgress(xmllocator->lineNumber()/100);
                                //                            kapp->processEvents();
#endif
//                            }
                        //}
                        currententry = ProtocolEntry();
                        // Fetch the name attribute.
                        i = atts.index(protocolnamespace.c_str(),nameattr.c_str());
                        if(i==-1) {
                        std::cout << "  errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND" << std::endl;
                            errorstate = PROTOCOL_ERROR_ENTRY_NAME_ATTR_NOT_FOUND;
                            return false;
                        }
                        currententry.setName( atts.value(i).toStdString() );
                        parsestate = PROTOCOL_STATE_ENTRY;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_ENTRY:
                    if(localName=="longname") {
                        loadlongname = false;
                        i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                        }
                        else
                        {
                            tmp = "en";
                        }
                        if(currententry.longnamelanguage.empty())
                        {
                            loadlongname = true;
                            currententry.longnamelanguage = tmp;
                        }
                        else
                        {
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
                    if(localName=="description")
                    {
                        loaddescription = false;
                        i = atts.index(protocolnamespace.c_str(),langattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                        } else {
                            tmp = "en";
                        }
                        if(currententry.descriptionlanguage.empty())
                        {
                            loaddescription = true;
                            currententry.descriptionlanguage = tmp;
                        }
                        else
                        {
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
                    if ( localName=="classification" )
                    {
                        i = atts.index(protocolnamespace.c_str(),classattr.c_str());
                        if ( i != -1 )
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="unknown")
                            {
                                currententry.classification = CLASS_UNKNOWN;
                            }
                            else if(tmp=="mail")
                            {
                                currententry.classification = CLASS_MAIL;
                            }
                            else if(tmp=="chat")
                            {
                                currententry.classification = CLASS_CHAT;
                            }
                            else if(tmp=="file")
                            {
                                currententry.classification = CLASS_FILE;
                            }
                            else if(tmp=="game")
                            {
                                currententry.classification = CLASS_GAME;
                            }
                            else if(tmp=="session")
                            {
                                currententry.classification = CLASS_SESSION;
                            }
                            else if(tmp=="data")
                            {
                                currententry.classification = CLASS_DATA;
                            }
                            else if(tmp=="media")
                            {
                                currententry.classification = CLASS_MEDIA;
                            }
                            else if(tmp=="net")
                            {
                                currententry.classification = CLASS_NET;
                            }
                            else
                            {
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
                            currententry.lastPragmaName = tmp;
                            currententry.pragma[tmp] = "";
                        }
//                        else {
//                            currententry.addPragmaame(std::string());  // Null string.
//                        }
                        parsestate = PROTOCOL_STATE_ENTRY_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_NETWORK:
                    if(localName=="tcp") {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_TCP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setSource( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setSource( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_TCP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setDest( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setDest( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_TCP_DEST_UNKNOWN;
                                return false;
                            }
                        }
                        parsestate = PROTOCOL_STATE_TCP;
                        return true;
                    }
                    if(localName=="udp")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_UDP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setSource( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setSource( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_UDP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setDest( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setDest( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_UDP_DEST_UNKNOWN;
                                return false;
                            }
                        }

                        // Check for direction attribute
                        i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                        if(i!=-1)
                        {
                            currentnetuse.setBidirectional( true );
                        }
                        parsestate = PROTOCOL_STATE_UDP;
                        return true;
                    }
                    if(localName=="icmp")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( IPPROTO_ICMP );
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setSource( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setSource( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_ICMP_SOURCE_UNKNOWN;
                                return false;
                            }
                        }
                        // Handle Dest attribute
                        i = atts.index(protocolnamespace.c_str(),destattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client")
                            {
                                currentnetuse.setDest( ENTITY_CLIENT );
                            }
                            else if(tmp=="server")
                            {
                                currentnetuse.setDest( ENTITY_SERVER );
                            }
                            else
                            {
                                errorstate = PROTOCOL_ERROR_ICMP_DEST_UNKNOWN;
                                return false;
                            }
                        }
                        parsestate = PROTOCOL_STATE_ICMP;
                        return true;
                    }
                    if(localName=="ip")
                    {
                        currentnetuse = ProtocolNetUse();
                        currentnetuse.setType( 0 );    // Dummy.

                        // Handle the Protocol attribute.
                        i = atts.index(protocolnamespace.c_str(),protocolattr.c_str());
                        if(i!=-1)
                        {
                            tmp = atts.value(i).toStdString();
                            try
                            {
                                ok = true;
                                x = boost::lexical_cast<uint>(tmp); //tmp.toUInt(&ok);
                            }
                            catch ( ... )
                            {
                                ok = false;
                            }
                            if(ok==false)
                            {
                                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_NOT_UINT;
                                return false;
                            }
                            if(x<0 || x>255)
                            {
                                errorstate = PROTOCOL_ERROR_IP_PROTOCOL_ATTR_OUT_OF_RANGE;
                                return false;
                            }
                            currentnetuse.setType( x );
                        }
                        else
                        {
                            errorstate = PROTOCOL_ERROR_IP_PROTOCOL_NOT_FOUND;
                            return false;
                        }
                        // Handle Source attribute
                        i = atts.index(protocolnamespace.c_str(),sourceattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                            if(tmp=="client") {
                                currentnetuse.setSource( ENTITY_CLIENT );
                            } else if(tmp=="server") {
                                currentnetuse.setSource( ENTITY_SERVER );
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
                                currentnetuse.setDest( ENTITY_CLIENT );
                            } else if(tmp=="server") {
                                currentnetuse.setDest( ENTITY_SERVER );
                            } else {
                                errorstate = PROTOCOL_ERROR_IP_DEST_UNKNOWN;
                                return false;
                            }
                        }

                        // Check for direction attribute
                        i = atts.index(protocolnamespace.c_str(),directionattr.c_str());
                        if(i!=-1) {
                            currentnetuse.setBidirectional( true );
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
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
//                        else {
//                            currentnetuse.addPragmaname(std::string());  // Null string.
//                        }
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
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
//                        else {
//                            currentnetuse.addPragmaname(std::string());  // Null string.
//                        }
                        parsestate = PROTOCOL_STATE_UDP_PRAGMA;
                        return true;
                    }
                    break;

                case PROTOCOL_STATE_ICMP:
                    if(localName=="type") {
                        currentnetusedetail = ProtocolNetUseDetail();
                        currentnetusedetail.setAlternate( false );
                        currentnetusedetail.setRangeType( PORTRANGE_RANGE );
                        currentnetusedetail.setCode( -1 );
                        // Grab the type number
                        i = atts.index(protocolnamespace.c_str(),valueattr.c_str());
                        if(i==-1) {
                            errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setType( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);
//                        if(ok==false) {
//                            errorstate = PROTOCOL_ERROR_TYPE_VALUE_ATTR_NOT_UINT;
//                            return false;
//                        }

                        // Grab the ICMP code.
                        i = atts.index(protocolnamespace.c_str(),codeattr.c_str());
                        if(i!=-1) {
                            tmp = atts.value(i).toStdString();
                            currentnetusedetail.setCode( boost::lexical_cast<uint>(tmp)); //tmp.toUInt(&ok);
//                            if(ok==false) {
//                                errorstate = PROTOCOL_ERROR_TYPE_CODE_ATTR_NOT_UINT;
//                                return false;
//                            }
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
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
//                        else {
//                            currentnetuse.addPragmaname(std::string());  // Null string.
//                        }
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
                            currentnetuse.lastPragmaName = tmp;
                            currentnetuse.pragma[tmp] = "";
                        }
//                        else {
//                            currentnetuse.addPragmaname(std::string());  // Null string.
//                        }
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
                        currentnetusedetail.setRangeType( PORTRANGE_RANGE );
                        currentnetusedetail.setAlternate( false );
                        currentnetusedetail.setStart( 0 );
                        currentnetusedetail.setEnd( 0 );

                        // Grab the port number
                        i = atts.index(protocolnamespace.c_str(),portnumattr.c_str());
                        if(i==-1) {
                            errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();

                        if(tmp=="any") {
                            currentnetusedetail.setRangeType( PORTRANGE_ANY );
                            currentnetusedetail.setStart( 0 );
                            currentnetusedetail.setEnd( 65535 );
                        } else if(tmp=="privileged") {
                            currentnetusedetail.setRangeType( PORTRANGE_PRIVILEGED );
                            currentnetusedetail.setStart( 0 );
                            currentnetusedetail.setEnd( 1023 );
                        } else if(tmp=="nonprivileged") {
                            currentnetusedetail.setRangeType( PORTRANGE_NONPRIVILEGED );
                            currentnetusedetail.setStart( 1024 );
                            currentnetusedetail.setEnd( 65535 );
                        } else if(tmp=="dynamic") {
                            currentnetusedetail.setRangeType( PORTRANGE_DYNAMIC );
                            currentnetusedetail.setStart( 1024 );
                            currentnetusedetail.setEnd( 65535 );
                        } else {
                            currentnetusedetail.setStart( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);
//                            if(ok==false) {
//                                errorstate = PROTOCOL_ERROR_PORT_PORTNUM_ATTR_NOT_UINT;
//                                return false;
//                            }
                            currentnetusedetail.setEnd( currentnetusedetail.getStart() );
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
                        currentnetusedetail.setRangeType( PORTRANGE_RANGE );
                        currentnetusedetail.setAlternate( false );
                        // Grab the start port number
                        i = atts.index(protocolnamespace.c_str(),portstartattr.c_str());
                        if(i==-1) {
                            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setStart( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);
//                        if(ok==false) {
//                            errorstate = PROTOCOL_ERROR_PORTRANGE_START_ATTR_NOT_UINT;
//                            return false;
//                        }

                        // Grab the end port number
                        i = atts.index(protocolnamespace.c_str(),portendattr.c_str());
                        if(i==-1) {
                            errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_FOUND;
                            return false;
                        }
                        tmp = atts.value(i).toStdString();
                        currentnetusedetail.setEnd( boost::lexical_cast<uint>(tmp) ); //tmp.toUInt(&ok);
//                        if(ok==false) {
//                            errorstate = PROTOCOL_ERROR_PORTRANGE_END_ATTR_NOT_UINT;
//                            return false;
//                        }
                        if(currentnetusedetail.getEnd() < currentnetusedetail.getStart())
                        {
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

    void doNetuseLanguage(const QXmlAttributes &atts)
    {
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
        }
        else
        {
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
    bool endElement(const QString &/*namespaceURI*/, const QString &/*localName*/, const QString &/*qName*/)
    {
        if(unknowndepth==0)
        {
            switch(parsestate) {
                case PROTOCOL_STATE_PROTOCOLDB:
                    parsestate = PROTOCOL_STATE_FINISHED;
                    return true;

                case PROTOCOL_STATE_ENTRY:
                    // We are just exiting an entry.
                    addProtocolEntry( currententry );
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
                    if(currentnetuse.numberSourcePorts()==0) {
                        ProtocolNetUseDetail currentnetusedetail;
                        currentnetusedetail.setRangeType( PORTRANGE_ANY );
                        currentnetusedetail.setAlternate( false );
                        currentnetusedetail.setStart( 0 );
                        currentnetusedetail.setEnd( 65535 );
                        currentnetuse.addSource( currentnetusedetail );
//                        currentnetuse.sourcedetaillist.push_back(currentnetusedetail);
                        //                    currentnetusedetail = 0;
                    }
                    if(currentnetuse.numberDestPorts()==0) {
                        ProtocolNetUseDetail currentnetusedetail;
                        currentnetusedetail.setRangeType( PORTRANGE_ANY );
                        currentnetusedetail.setAlternate( false );
                        currentnetusedetail.setStart( 0 );
                        currentnetusedetail.setEnd( 65535 );
                        currentnetuse.addDest( currentnetusedetail );
                        //                    currentnetusedetail = 0;
                    }
                    // This fall through is intentional.
                case PROTOCOL_STATE_ICMP:
                case PROTOCOL_STATE_IP:
                    currententry.addNetwork( currentnetuse ); //networkuse.push_back(currentnetuse);
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
                    currentnetuse.addSource(currentnetusedetail);
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
                    currentnetuse.addSource(currentnetusedetail);
                    //                currentnetusedetail = 0;
                    parsestate = PROTOCOL_STATE_TCP_SOURCE;
                    return true;

                case PROTOCOL_STATE_TCP_DEST_PORT:
                case PROTOCOL_STATE_TCP_DEST_PORTRANGE:
                    currentnetuse.addDest(currentnetusedetail);
                    //                currentnetusedetail = 0;
                    parsestate = PROTOCOL_STATE_TCP_DEST;
                    return true;

                case PROTOCOL_STATE_UDP_SOURCE_PORT:
                case PROTOCOL_STATE_UDP_SOURCE_PORTRANGE:
                    currentnetuse.addSource(currentnetusedetail);
                    //                currentnetusedetail = 0;
                    parsestate = PROTOCOL_STATE_UDP_SOURCE;
                    return true;

                case PROTOCOL_STATE_UDP_DEST_PORT:
                case PROTOCOL_STATE_UDP_DEST_PORTRANGE:
                    currentnetuse.addDest(currentnetusedetail);
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

    bool characters(const QString &ch)
    {
        if ( unknowndepth )
        {
            return true;
        }

        switch ( parsestate )
        {
            case PROTOCOL_STATE_LONGNAME:
                if(loadlongname)
                {
                    currententry.longname = ch.toStdString();
                }
                return true;

            case PROTOCOL_STATE_DESCRIPTION:
                if ( loaddescription )
                {
                    currententry.description = ch.toStdString();
                }
                return true;

            case PROTOCOL_STATE_ENTRY_PRAGMA:
                currententry.addPragmaValue(ch.toStdString());
                return true;

            case PROTOCOL_STATE_TCP_DESCRIPTION:
            case PROTOCOL_STATE_UDP_DESCRIPTION:
            case PROTOCOL_STATE_ICMP_DESCRIPTION:
                if ( loaddescription )
                {
                    currentnetuse.description = ch.toStdString();
                }
                return true;

            case PROTOCOL_STATE_TCP_PRAGMA:
            case PROTOCOL_STATE_UDP_PRAGMA:
            case PROTOCOL_STATE_ICMP_PRAGMA:
                currentnetuse.addPragmaValue(ch.toStdString());
                return true;

            default:
                break;
        }
        return true;
    }

    ///////////////////////////////////////////////////////////////////////////
    bool error(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }

    ///////////////////////////////////////////////////////////////////////////
    bool fatalError(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }

    ///////////////////////////////////////////////////////////////////////////
    bool warning(const QXmlParseException &exception)
    {
        printParseException(exception);
        errorstate = PROTOCOL_ERROR_PARSE_ERROR;
        return false;
    }

    ///////////////////////////////////////////////////////////////////////////
    QString errorString() const
    {
        switch(errorstate)
        {
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
                    return message.c_str();
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
    void printParseException(const QXmlParseException &exception)
    {
        std::stringstream ss;
        ss << "Line: " << exception.lineNumber() << ", "
            << "Column: " << exception.columnNumber() << " " << exception.systemId().toStdString() << ", "
            << exception.publicId().toStdString() << ", " << exception.message().toStdString() << std::endl;
        parseerror.push_back( ss.str() );
    }

    ProtocolEntry & lookup( std::string const & name )
    {

        std::vector< ProtocolEntry >::iterator pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::name, boost::phoenix::arg_names::arg1) == name );
        if ( pit == protocolDataBase.end() )
        {
            pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::longname, boost::phoenix::arg_names::arg1) == name );
            if ( pit == protocolDataBase.end() )
            {
                std::cout << "Didn't protocol database: " << name << std::endl;
                throw std::string("Zone not found 4");
            }
        }
        return *pit;
    }

    ProtocolEntry const & lookup( std::string const & name ) const
    {

        std::vector< ProtocolEntry >::const_iterator pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::name, boost::phoenix::arg_names::arg1) == name );
        if ( pit == protocolDataBase.end() )
        {
            pit = std::find_if( protocolDataBase.begin(), protocolDataBase.end(), boost::phoenix::bind( &ProtocolEntry::longname, boost::phoenix::arg_names::arg1) == name );
            if ( pit == protocolDataBase.end() )
            {
                std::cout << "Didn't protocol database: " << name << std::endl;
                throw std::string("Zone not found 5");
            }
        }
        return *pit;

//        X x(name );
//        return std::find_if( protocolDataBase.begin(), protocolDataBase.end(), x );
    }


};

