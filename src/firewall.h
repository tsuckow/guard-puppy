#pragma once

#include <fstream>
#include <iostream>

#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/spirit/home/phoenix/core.hpp>
#include <boost/spirit/home/phoenix/operator.hpp>
#include <boost/spirit/home/phoenix/bind.hpp>

#include "protocoldb.h"
#include "userdefinedprotocol.h"
#include "zone.h"

#define SYSTEM_RC_FIREWALL "/etc/rc.firewall" 
#define SYSTEM_RC_FIREWALL2 "/etc/rc2.firewall" 

enum { LOG_WARNING };

class GuardPuppyFireWall
{
    ProtocolDB  pdb;                // The protocol database we are using.
    bool modified;
    bool waspreviousfirewall;       // True if there was a previous Guarddog firewall active/available
                                    // at program startup.
    bool systemfirewallmodified;    // True if the current state of the system has been modified
                                    // since program startup. This is needed at 'Cancel' time when
                                    // we need to decide if we have any 'Apply'ed changes that need
                                    // to be undone.

    bool superUserMode;

    enum LogRateUnit {SECOND=0, MINUTE, HOUR, DAY};

    std::vector< Zone > zones;

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
    std::string dhcpcinterfacename;
    bool dhcpdenabled;
    std::string dhcpdinterfacename;
    bool allowtcptimestamps;

    std::vector< UserDefinedProtocol > userdefinedprotocols;

public:
    std::string description;

    //  TODO delete this once the FOREACH code in dialog_w.cpp is
    //  ported to a function here.
    std::vector< ProtocolEntry > const & getProtocolDataBase() const
    {
        return pdb.getProtocolDataBase();
    }

    std::string getProtocolText( std::string const & protocol )
    {
        std::string text = "Not found";
        try
        {
            text = pdb.lookup( protocol ).description;
        }
        catch(...)
        {
        }
        return text;
    }

    void setLogDrop(bool on) { logdrop = on; }
    bool isLogDrop() { return logdrop; }
    void setLogReject(bool on) { logreject = on; }
    bool isLogReject() { return logreject; }
    void setLogIPOptions(bool on) { logipoptions = on; }
    bool isLogIPOptions() { return logipoptions; }
    void setLogTCPOptions(bool on) { logtcpoptions = on; }
    bool isLogTCPOptions() { return logtcpoptions; }
    void setLogTCPSequence(bool on) { logtcpsequence = on; }
    bool isLogTCPSequence() { return logtcpsequence; }
    void setLogAbortedTCP(bool on) { logabortedtcp = on; }
    bool isLogAbortedTCP() { return logabortedtcp; }
    void setLogLevel(uint level) { loglevel = level; }
    uint getLogLevel() { return loglevel; }
    void setLogRateLimit(bool on) { logratelimit = on; }
    bool isLogRateLimit() { return logratelimit; }
    void setLogRate(uint hitsper) { lograte = hitsper; }
    uint getLogRate() { return lograte; }
    void setLogRateUnit(LogRateUnit unit) { lograteunit = unit; }
    LogRateUnit getLogRateUnit() { return lograteunit; }
    void setLogRateBurst(uint burst) { lograteburst = burst; }
    uint getLogRateBurst() { return lograteburst; };
    void setLogWarnLimit(bool on) { logwarnlimit = on; }
    bool isLogWarnLimit() { return logwarnlimit; }
    void setLogWarnLimitRate(uint hitsper) { logwarnrate = hitsper; }
    uint getLogWarnLimitRate() { return logwarnrate; }
    void setLogWarnLimitRateUnit(LogRateUnit unit) { logwarnrateunit = unit; }
    LogRateUnit getLogWarnLimitRateUnit() { return logwarnrateunit; }
    void setDHCPcEnabled(bool on) { dhcpcenabled = on; }
    bool isDHCPcEnabled() { return dhcpcenabled; }
    void setDHCPdEnabled(bool on) { dhcpdenabled = on; }
    bool isDHCPdEnabled() { return dhcpdenabled; }
    void setAllowTCPTimestamps(bool on) { allowtcptimestamps = on; }
    bool isAllowTCPTimestamps() { return allowtcptimestamps; }

    void addNewMachine( std::string const & zoneName, std::string const & ipAddress )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << zoneName << std::endl;
            throw std::string("Zone not found");
        }
        zit->addMemberMachine( IPRange( ipAddress ) );
    }
    void deleteMachine( std::string const & zoneName, std::string const & ipAddress )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << zoneName << std::endl;
            throw std::string("Zone not found");
        }
        zit->deleteMemberMachine( IPRange( ipAddress ) );
    }
    void setNewMachineName( std::string const & zoneName, std::string const & oldMachineName, std::string const & newMachineName )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << zoneName << std::endl;
            throw std::string("Zone not found");
        }
        zit->renameMachine( oldMachineName, newMachineName );

    }

    void setProtocolState( std::string const & fromZone, std::string const & toZone, std::string const & protocolName, Zone::ProtocolState state )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == fromZone );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << fromZone << std::endl;
            throw std::string("Zone not found");
        }

        return zit->setProtocolState( toZone, protocolName, state );

    }


    Zone::ProtocolState getProtocolState( std::string const & fromZone, std::string const & toZone, std::string const & protocolName )
    {
        std::vector< Zone >::const_iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == fromZone );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << fromZone << std::endl;
            throw std::string("Zone not found");
        }

        return zit->getProtocolState( toZone, protocolName );

    }

    std::vector< std::string > getZoneList() const
    {
        std::vector< std::string > names;
        BOOST_FOREACH( Zone const & z, zones )
        {
            names.push_back( z.getName() );
        }
        return names;
    }

    size_t zoneCount() const { return zones.size(); }


    void addZone( std::string const & zoneName )
    {
        zones.push_back( Zone( zoneName ) );
    }

    void deleteZone( std::string const & zoneName )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneName );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << zoneName << std::endl;
            throw std::string("Zone not found");
        }
        zones.erase( zit );
    }
#if 1
    Zone const & getZone( std::string const & name = "" ) const
    {
        std::vector< Zone >::const_iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );    
        if ( zit == zones.end() )
        {
            std::cout << "getZone() Didn't find zone name: " << name << std::endl;
            throw std::string("Zone not found");
        }
        return *zit;
    }
    Zone & getZone( std::string const & name = "" )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == name );    
        if ( zit == zones.end() )
        {
            std::cout << "getZone() Didn't find zone name: " << name << std::endl;
            throw std::string("Zone not found");
        }
        return *zit;
    }
#endif
    std::vector< std::string > getConnectedZones( std::string const & zoneFrom ) const
    {
        std::vector< std::string > connectedZones;

        BOOST_FOREACH( std::string const & zoneTo, getZoneList() )
        {
            if ( areZonesConnected( zoneFrom, zoneTo ) )
            {
                connectedZones.push_back( zoneTo );
            }
        }

        return connectedZones;
    }

    void updateZoneConnection( std::string const & fromZone, std::string const & toZone, bool connected )
    {
        std::cout << "updateZoneConnection " << fromZone << " to " << toZone << " " << connected << std::endl;
        if ( connected )
        {
            getZone( fromZone ).connect( toZone );
        }
        else
        {
            getZone( fromZone ).disconnect( toZone );
        }
    }

    std::vector< std::string > getConnectedZoneProtocols( std::string const & fromZone, std::string const & toZone, Zone::ProtocolState state ) const
    {
        return getZone( fromZone ).getConnectedZoneProtocols( toZone, state );
    }

    bool areZonesConnected( std::string const & zoneFrom, std::string const & zoneTo ) const
    {
        std::vector< Zone >::const_iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == zoneFrom );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << zoneFrom << std::endl;
            return false;
        }
        return zit->isConnected( zoneTo );
    }

    void setNewZoneName( std::string const & oldZoneName, std::string const & newZoneName )
    {
        std::vector< Zone >::iterator zit = std::find_if( zones.begin(), zones.end(), boost::phoenix::bind( &Zone::getName, boost::phoenix::arg_names::arg1) == oldZoneName );    
        if ( zit == zones.end() )
        {
            std::cout << "Didn't find zone name: " << oldZoneName << std::endl;
            throw ( "setNewZoneName" );
        }
        zit->setName( newZoneName );
    }

public:
    std::vector< UserDefinedProtocol > const & getUserDefinedProtocols() const
    {
        return userdefinedprotocols;
    }
    GuardPuppyFireWall( bool superuser )
        : pdb( "protocoldb/networkprotocoldb.xml" ), superUserMode( superuser ) //, gui( _gui )
    {
        //        std::string protocollocation = "protocoldb/networkprotocoldb.xml";

        //        if(!pdb->loadDB(protocollocation, QStringList("English") )) {
        //            QMessageBox::critical(0,"networkprotocoldb",tr("An error occured while reading the protocol database.\n\nDetails: \"%1\"").arg(pdb->errorString()));
        //            throw "terminating";
        //        }
        try 
        {
            readOptions();
            factoryDefaults();
            openDefault();
        }
        catch ( std::string const & msg )
        {
            std::cout << "Exception: " << msg << std::endl;
        }
    }
    void setDisabled(bool on) {
        disabled = on;
    }

    bool isDisabled() {
        return disabled;
    }
    void setLocalDynamicPortRange(uint start,uint end) {
        localPortRangeStart = start;
        localPortRangeEnd = end;
    }

    void getLocalDynamicPortRange(uint &start,uint &end) {
        start = localPortRangeStart;
        end = localPortRangeEnd;
    }

    void setDHCPcInterfaceName(const std::string &ifacename) {
        dhcpcinterfacename = ifacename;
    }

    std::string getDHCPcInterfaceName() {
        return dhcpcinterfacename;
    }

    void setDHCPdInterfaceName(const std::string &ifacename) {
        dhcpdinterfacename = ifacename;
    }

    std::string getDHCPdInterfaceName() {
        return dhcpdinterfacename;
    }

    bool isSuperUserMode() const 
    {
        return superUserMode;
    }

    void save() 
    {
        std::string errorstring;
        //        std::string filename( SYSTEM_RC_FIREWALL );
        std::string filename( SYSTEM_RC_FIREWALL2 );
        std::cout << "Saving firewall " << filename << std::endl;

        if ( modified ) 
        {
            saveFirewall( filename );
            applyFirewall(true);
            saveOptions();
            saveOptions();
        }
    }

    void saveOptions() 
    {
        //    KConfig *config;
        //    config = kapp->config();

        //    config->setGroup("General");
        //    config->writeEntry("Geometry", size());
        //    config->writeEntry("CommandrunnerGeometry",commandrunnersize);
        //    config->writeEntry("ShowAdvancedHelp",showadvancedhelp);
        //    config->sync();
    }
    ///////////////////////////////////////////////////////////////////////////
    void readOptions() 
    {
#if 0
        KConfig *config;
        config = kapp->config();

        config->setGroup("General");
        QSize size = config->readSizeEntry("Geometry");
        if(!size.isEmpty()) {
            resize(size);
        }
        commandrunnersize = config->readSizeEntry("CommandrunnerGeometry");
        if(commandrunnersize.isEmpty()) {
            commandrunnersize.setWidth(400);
            commandrunnersize.setHeight(300);
        }
        showadvancedhelp = config->readBoolEntry("ShowAdvancedHelp");
        showadvancedhelpcheckbox->setChecked(showadvancedhelp);
#endif
    }


    bool applyFirewall(bool /* warnfirst */) 
    {
#if 0
        std::string errorstring;
        KTempFile tmpfile(0,0,0700);
        CommandRunner cr(this);

        tmpfile.setAutoDelete(true);

        if(doc->isDisabled()==false) {
            // Normal firewall apply.
            if(warnfirst==false || KMessageBox::warningContinueCancel(this,
                        i18n("You are about to modify the system's firewall configuration.\n"
                            "These changes may disrupt current network connections.\n\n"
                            "Do you wish to continue?"),0,i18n("Continue"))==KMessageBox::Continue) {

                // Is our temp file working?
                if(tmpfile.status()!=0) {
                    KMessageBox::error(this,i18n("An error occurred while trying to modify system's firewall configuration.\nThe operating system has this to report about the error: %1")
                            .arg(strerror(tmpfile.status())));
                    return false;
                }
                // Write the firewall script into the temp file.
                if(doc->writeFirewall(*(tmpfile.textStream()),errorstring)==false) {
                    return false;
                }
                // Close and flush the file.
                if(!tmpfile.close()) {
                    KMessageBox::error(this,i18n("An error occurred while applying the firewall.\nThe operating system has this to report about the error: %1")
                            .arg(strerror(tmpfile.status())));
                    return false;
                }
                // Now we run the tmp script in our super friendly firewall starter
                // window.
                if(!commandrunnersize.isEmpty()) {
                    cr.resize(commandrunnersize);
                }
                cr.setPlainCaption(i18n("Starting firewall"));
                cr.setHeading(i18n("Starting firewall...\n\nOutput:"));
                cr.run(std::string("export GUARDDOG_VERBOSE=1;")+tmpfile.name());
                systemfirewallmodified = true;
                commandrunnersize = cr.size();
                return true;
            }
            return false;
        } else {
            // If we are to actually disable the firewall because the user has set
            // the Disable checkbox in the advanced section, then we use a different
            // warning question and use a different method to reset the network stack.
            if(warnfirst==false || KMessageBox::warningContinueCancel(this,
                        i18n("You are about to disable the system's firewall.\n"
                            "This will allow all network traffic and potentially leave your system vulnerable to attack.\n"
                            "Unless you are an advanced user and know what you are doing I recommend that you cancel this action.\n"
                            "These changes may also disrupt current network connections.\n\n"
                            "Do you wish to continue?"),0,i18n("Continue"))==KMessageBox::Continue) {

                if(resetSystemFirewall()) {
                    systemfirewallmodified = true;
                    return true;
                } else {
                    return false;
                }
            }
            return false;
        }
#endif
        return false;
    }
    // true if application should close
    void copyFile( std::string const & src,  std::string const & dest ) 
    {
        boost::filesystem::copy_file( src, dest, boost::filesystem::copy_option::overwrite_if_exists );
    }
    void openDefault() 
    {
        std::cout << "openDefault" << std::endl;
        std::string filename(SYSTEM_RC_FIREWALL);
        std::string errorstring;
        std::ifstream fileinfo( SYSTEM_RC_FIREWALL );

        if ( superUserMode==false ) 
        {
            return; // Sorry, if you are not root then you get no default firewall.
        }

        if ( !fileinfo ) 
        {
            // There doesn't appear to be a previous Guarddog firewall script.
            // Just warn the user about the ramifications.
            throw ( "Guarddog was unable to find a Guarddog firewall at " + filename + "\n"
                    "This is probably ok, it just means that this is the first time Guarddog has been run on this system.\n"
                    "But please be aware that the firewall settings shown may not represent the system's current firewalling configuration.\n"
                    "Your Guarddog firewall will take effect once you use the 'Apply' button or exit Guarddog using 'Ok'.");
        } 
        else 
        {
            if ( openFirewall(filename,errorstring)==false) 
            {
                factoryDefaults();
                // We were unable to open the guarddog firewall.
                throw ("Guarddog was unable to read the file at " + filename + " as being a Guarddog firewall.\n"
                        "This probably means that this file in not actually a Guarddog firewall.\n"
                        "This is not a problem, but please note that if you exit Guarddog via the 'Ok' button this file will be overwritten.\n"
                        "If you do not want this to happen, then after closing this message, immediately quit Guarddog using the 'Cancel' button.\n"
                        "Also please be aware that the firewall settings shown may not represent the system's current firewalling configuration.\n\n"
                        "(Detailed message \"" + errorstring + "\")");
            } 
            else 
            {
                waspreviousfirewall = true;
            }
        }
        // Backup the firewall.
        copyFile(SYSTEM_RC_FIREWALL,SYSTEM_RC_FIREWALL "~");
    }

    std::vector< ProtocolNetUse > getNetworkUse( std::string const & protocolName ) const
    {
        std::vector< ProtocolNetUse > protos = pdb.getNetworkUses( protocolName );
        BOOST_FOREACH( UserDefinedProtocol const & udp, userdefinedprotocols )
        {
            protos.push_back( udp.netuse );
        }
        return protos;
    }

//    void deleteUserDefinedProtocol(UserDefinedProtocol *thisudp) 
//    {
#if 0
        //    QList<Zone *>::iterator zit;

        // We have to tell the Zones not to reference this protocol
        // before we delete it out from under them.
        //    zit = zones.begin();
        //    for(;zit->current(); ++(*zit)) {
        BOOST_FOREACH( Zone & zit, zones ) {
            zit.deleteProtocol(thisudp->getProtocolEntry());
        }
        //    delete zit;

        userdefinedprotocols.removeAt(userdefinedprotocols.find(thisudp));
#endif
//    }

    ///////////////////////////////////////////////////////////////////////////
#if 0
    UserDefinedProtocol *newUserDefinedProtocol() {
        UserDefinedProtocol *newudp;
        uint i;
        bool hit;

        // Find a unique ID. It's O(n^2) but the list should always be small.
        // ooooh I always feel guilty coding a O(n^2) algo.
        hit = true;
        i = 0;
        while(hit) {
            i++;
            hit = false;
            //        for(p=userdefinedprotocols.first(); p!=0; p=userdefinedprotocols.next()) {
            BOOST_FOREACH( UserDefinedProtocol const & p, userdefinedprotocols ) {
                if(p.getID()==i) {
                    hit = true;
                    break;
                }
            }
        }

        newudp = new UserDefinedProtocol(&pdb,i);
        newudp->setName(("new"));
        userdefinedprotocols.append(newudp);
        return newudp;
        }
#endif

        bool writeFirewall( std::ostream & stream )
        {
            std::vector<Zone>::iterator zit,zit2;
            int c,oldc;

            zit = zones.begin();
            zit2 = zones.begin();

            stream<<"#!/bin/bash\n"
                "# [Guarddog2]\n"
                "# DO NOT EDIT!\n"
                "# This firewall script was generated by \"Guarddog\" by Simon Edwards\n"
                "# http://www.simonzone.com/software/guarddog/ This script requires Linux\n"
                "# kernel version 2.2.x and ipchains OR Linux kernel 2.4.x and iptables.\n"
                "#\n"
                "# [Description]\n";
            c = 0;
            oldc = 0;
            while((c = description.find('\n',c))>=0) {
                stream<<"#  "<<description.substr(oldc,c-oldc)<<"\n";
                oldc = c + 1;
                c++;
            }
            c = (int)description.length();
            stream<<"#  "<<description.substr(oldc,c-oldc)<<"\n";

            stream<<	
                "# [Config]\n"
                "# LOCALPORTRANGESTART="<<localPortRangeStart<<"\n"
                "# LOCALPORTRANGEEND="<<localPortRangeEnd<<"\n"
                "# DISABLED="<<(disabled?1:0)<<"\n"
                "# LOGREJECT="<<(logreject?1:0)<<"\n"
                "# LOGDROP="<<(logdrop?1:0)<<"\n"
                "# LOGABORTEDTCP="<<(logabortedtcp?1:0)<<"\n"
                "# LOGIPOPTIONS="<<(logipoptions?1:0)<<"\n"
                "# LOGTCPOPTIONS="<<(logtcpoptions?1:0)<<"\n"
                "# LOGTCPSEQUENCE="<<(logtcpsequence?1:0)<<"\n"
                "# LOGLEVEL="<<(loglevel)<<"\n"
                "# LOGRATELIMIT="<<(logratelimit?1:0)<<"\n"
                "# LOGRATE="<<lograte<<"\n"
                "# LOGRATEUNIT="<<((uint)lograteunit)<<"\n"
                "# LOGRATEBURST="<<lograteburst<<"\n"
                "# LOGWARNLIMIT="<<(logwarnlimit?1:0)<<"\n"
                "# LOGWARNRATE="<<logwarnrate<<"\n"
                "# LOGWARNRATEUNIT="<<((uint)logwarnrateunit)<<"\n"
                "# DHCPC="<<(dhcpcenabled?1:0)<<"\n"
                "# DHCPCINTERFACENAME="<<(dhcpcinterfacename)<<"\n"
                "# DHCPD="<<(dhcpdenabled?1:0)<<"\n"
                "# DHCPDINTERFACENAME="<<(dhcpdinterfacename)<<"\n"
                "# ALLOWTCPTIMESTAMPS="<<(allowtcptimestamps?1:0)<<"\n";

            // Output the info about the Zones we have. No need to output the default zones.
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                if(zit.editable()) 
                {
                    stream<<"# [Zone]\n";
                    stream<<"# NAME="<<(zit.getName().c_str())<<"\n";
                    stream<<"# COMMENT="<<(zit.getComment())<<"\n";
                    BOOST_FOREACH( IPRange const & addy, zit.getMemberMachineList() ) 
                    {
                        stream<<"# ADDRESS="<<addy.getAddress()<<"\n";
                    }
                }
            }

            // Output the User Defined Protocols
//            for(size_t i=0; i<userdefinedprotocols.size(); i++) 
            BOOST_FOREACH( UserDefinedProtocol const & currentudp, getUserDefinedProtocols() )
            {
//                UserDefinedProtocol & currentudp = userdefinedprotocols.at(i);
                stream<<"# [UserDefinedProtocol]\n";
                stream<<"# ID="<<(currentudp.getID())<<"\n";
                stream<<"# NAME="<<(currentudp.getName())<<"\n";
                stream<<"# TYPE="<<(currentudp.getType()==IPPROTO_TCP ? "TCP" : "UDP")<<"\n";
                stream<<"# PORT="<<currentudp.getStartPort()<<":"<<currentudp.getEndPort()<<"\n";
                stream<<"# BIDIRECTIONAL="<<(currentudp.isBidirectional() ? 1 : 0)<<"\n";
            }

            // Go over each Zone and output which protocols are allowed to whom.
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                stream<<"# [ServerZone] "<<(zit.getName().c_str())<<"\n";

                // Iterate over each possible client zone.
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( zit != zit2) 
                    {
                        stream<<"# [ClientZone] " << zit2.getName() <<"\n";

                        if ( areZonesConnected(zit.getName(), zit2.getName())) 
                        {
                            stream<<"# CONNECTED=1\n";
                            // Now we iterate over and output each enabled protocol.
                            //                    protodictit = zit.newPermitProtocolZoneIterator(zit2);
                            std::vector< std::string > zones1 = getConnectedZoneProtocols( zit.getName(), zit2.getName(), Zone::PERMIT );
                            BOOST_FOREACH( std::string const & p, zones1 )
                            {
                                stream << "# PROTOCOL=" << p << std::endl;
                            }

                            // Output each Rejected protocol.
                            std::vector< std::string > zones2 = getConnectedZoneProtocols( zit.getName(), zit2.getName(), Zone::REJECT );
                            BOOST_FOREACH( std::string const & p, zones2 )
                            {
                                stream << "# REJECT=" << p << std::endl;
                            }
                        } 
                        else 
                        {
                            // This server/client zone combo is not currently connected.
                            stream<<"# CONNECTED=0\n";
                        }
                    }
                }
            }

            // The real script starts here.
            stream<<"# [End]\n"
                "\n"
                "# Real code starts here\n"
                "# If you change the line below then also change the # DISABLED line above.\n";
            if(disabled) 
            {
                stream<<"DISABLE_GUARDDOG=1\n";
            } 
            else 
            {
                stream<<"DISABLE_GUARDDOG=0\n";
            }
            stream<<"if test -z $GUARDDOG_VERBOSE; then\n"
                "  GUARDDOG_VERBOSE=0\n"
                "fi;\n"
                "if [ $DISABLE_GUARDDOG -eq 0 ]; then\n"
                "# Set the path\n"
                "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin\n"
                "# Detect which filter command we should use.\n"
                "FILTERSYS=0\n"
                "# 0 = unknown, 1 = ipchains, 2 = iptables\n"
                "# Check for ipchains.\n"
                "if [ -e /sbin/ipchains ]; then\n"
                "  FILTERSYS=1\n"
                "fi;\n"
                "if [ -e /usr/sbin/ipchains ]; then\n"
                "  FILTERSYS=1\n"
                "fi;\n"
                "if [ -e /usr/local/sbin/ipchains ]; then\n"
                "  FILTERSYS=1\n"
                "fi;\n"
                "# Check for iptables support.\n"
                "if [ -e /proc/sys/kernel/osrelease ]; then\n"
                "  KERNEL_VERSION=`sed \"s/^\\([0-9][0-9]*\\.[0-9][0-9]*\\).*\\$/\\1/\" < /proc/sys/kernel/osrelease`\n"
                "  if [ $KERNEL_VERSION == \"2.6\" ]; then\n"
                "    KERNEL_VERSION=\"2.4\"\n"
                "  fi;\n"
                "  if [ $KERNEL_VERSION == \"2.5\" ]; then\n"
                "    KERNEL_VERSION=\"2.4\"\n"
                "  fi;\n"
                "  if [ $KERNEL_VERSION == \"2.4\" ]; then\n"
                "    if [ -e /sbin/iptables ]; then\n"
                "      FILTERSYS=2\n"
                "    fi;\n"
                "    if [ -e /usr/sbin/iptables ]; then\n"
                "      FILTERSYS=2\n"
                "    fi;\n"
                "    if [ -e /usr/local/sbin/iptables ]; then\n"
                "      FILTERSYS=2\n"
                "    fi;\n"
                "  fi;\n"
                "fi;\n"
                "if [ $FILTERSYS -eq 0 ]; then\n"
                "  logger -p auth.info -t guarddog \"ERROR Can't determine the firewall command! (Is ipchains or iptables installed?)\"\n"
                "  [ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<< ("ERROR Can't determine the firewall command! (Is ipchains or iptables installed?)")<<"\"\n"
                "  false\n"
                "fi;\n"
                //                        "if [ $FILTERSYS -eq 1 ]; then\n";
                //                    writeIPChainsFirewall(stream);
                //                    stream<<"fi;\n"
                "if [ $FILTERSYS -eq 2 ]; then\n";
            writeIPTablesFirewall(stream);
            stream<<"fi;\n"
                "fi;\n" // Matches the disable firewall IF.
                "true\n";

            //    delete zit;
            //    delete zit2;

            return true;
        }

        void writeIPTablesFirewall(std::ostream &stream) 
        {
            //                            QList<Zone*>::iterator zit,zit2;
            PortRangeInfo localPRI;
            //                            QPtrDictIterator<ProtocolEntry> *protodictit;
            //                            IPRange *addy;
//            uint i,j;
//            int mask;
            //                            QStringList::Iterator pragmanameit;
            //                            QStringList::Iterator pragmavalueit;
            //                            QStringList::Iterator moduleit;
            //                            QStringList modules;
            const char *rateunits[] = {"second", "minute", "hour", "day" };
            //                            zit = zones.begin();
            //                            zit2 = zones.begin();

            uint localindex = 0;
            uint internetindex = 0;

            // Work out what the indexes of the local zone and internet zone are.
            BOOST_FOREACH( Zone const & zit, zones )
            {
                if ( zit.isLocal() )
                    localindex = zit.getId();
                if ( zit.isInternet() )
                    internetindex = zit.getId();
            }

            stream<<"###############################\n"
                "###### iptables firewall ######\n"
                "###############################\n"
                "logger -p auth.info -t guarddog Configuring iptables firewall now.\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Using iptables.")<<"\"\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Resetting firewall rules.")<<"\"\n"
                "# Shut down all traffic\n"
                "iptables -P FORWARD DROP\n"
                "iptables -P INPUT DROP\n"
                "iptables -P OUTPUT DROP\n"
                "\n"
                "# Delete any existing chains\n"
                "iptables -F\n"
                "iptables -X\n"
                "\n"
                "# Load any special kernel modules.\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Loading kernel modules.")<<"\"\n";

            // Examine all of the allowed protocols in all the zones etc and look for
            // guarddog pragmas that indicate extra kernel modules that should be loaded.
            // Build a list of the extra kernel modules we need.

            // 'From' zone loop
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                // 'To' zone loop
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( zit != zit2 ) 
                    {
#if 0
                        protodictit = zit2->current()->newPermitProtocolZoneIterator(zit->current());
                        if(protodictit!=0) 
                        {
                            for(;protodictit->current(); ++(*protodictit)) 
                            {
                                pragmanameit = protodictit->current()->pragmaname.begin();
                                pragmavalueit = protodictit->current()->pragmavalue.begin();
                                for(; pragmanameit!=protodictit->current()->pragmaname.end(); ++pragmanameit) 
                                {
                                    if(*pragmanameit =="guarddog") 
                                    {
                                        // Only add a module to the list if we don't have it already.
                                        gotmodule = false;
                                        for(moduleit = modules.begin(); moduleit!=modules.end(); ++moduleit) 
                                        {
                                            if(*moduleit==*pragmavalueit) 
                                            {
                                                gotmodule = true;
                                                break;
                                            }
                                        }
                                        if(gotmodule==false) 
                                        {
                                            modules.append(*pragmavalueit);
                                        }
                                    }
                                    ++pragmavalueit;
                                }
                            }
                            delete protodictit;
                        }
#endif
                    }
                }
            }
            std::vector< std::string > modules;
            BOOST_FOREACH( std::string const & m, modules )
            {
                // Output the modprobe code to load the extra modules.
                stream << "modprobe " << m << std::endl;
            }

            stream<<"\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Setting kernel parameters.")<<"\"\n"
                "# Turn on kernel IP spoof protection\n"
                "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2> /dev/null\n"
                "# Set the TCP timestamps config\n"
                "echo "<<(allowtcptimestamps ? "1" : "0")<<" > /proc/sys/net/ipv4/tcp_timestamps 2> /dev/null\n"
                "# Enable TCP SYN Cookie Protection if available\n"
                "test -e /proc/sys/net/ipv4/tcp_syncookies && echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2> /dev/null\n"
                "echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 2> /dev/null\n"
                "echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route 2> /dev/null\n"
                "# Log truly weird packets.\n"
                "echo 1 > /proc/sys/net/ipv4/conf/all/log_martians 2> /dev/null\n"
                "echo 1 > /proc/sys/net/ipv4/conf/default/log_martians 2> /dev/null\n"
                "# Switch the current language for a moment\n"
                "GUARDDOG_BACKUP_LANG=$LANG\n"
                "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
                "LANG=US\n"
                "LC_ALL=US\n"
                "export LANG\n"
                "export LC_ALL\n"
                "# Set kernel rp_filter. NICs used for IPSEC should not have rp_fitler turned on.\n"
                "# Find the IPs of any ipsecX NICs\n"
                "IPSEC_IPS=\"`ifconfig | gawk '/^ipsec\\w/ { grabip = 1}\n"
                "/inet addr:[[:digit:]\\\\.]+/ { if(grabip==1) printf \\\"%s \\\",gensub(/^.*inet addr:([[:digit:]\\\\.]+).*$/,\\\"\\\\\\\\1\\\",\\\"g\\\",$0)\n"
                "grabip = 0}'`\"\n"
                "# Build a list of NIC names and metching IPs\n"
                "IP_NIC_PAIRS=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",$1)}\n"
                "/inet addr:.*/ {match($0,/inet addr:[[:digit:]\\.]+/)\n"
                "ip=substr($0,RSTART+10,RLENGTH-10)\n"
                "printf \\\"%s_%s\\\\n\\\",nic,ip }'`\"\n"
                "\n"
                "# Restore the language setting\n"
                "LANG=$GUARDDOG_BACKUP_LANG\n"
                "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
                "export LANG\n"
                "export LC_ALL\n"
                "\n"
                "# Activate rp_filter for each NIC, except for NICs that are using\n"
                "# an IP that is involved with IPSEC.\n"
                "for X in $IP_NIC_PAIRS ; do\n"
                "  NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
                "  IP=\"`echo \\\"$X\\\" | cut -f 2 -d _`\"\n"
                "  RPF=\"1\"\n"
                "  for SEC_IP in $IPSEC_IPS ; do\n"
                "    if [[ $SEC_IP == $IP ]]; then\n"
                "      RPF=\"0\"\n"
                "    fi\n"
                "  done\n"
                "  echo $RPF > /proc/sys/net/ipv4/conf/$NIC/rp_filter 2> /dev/null\n"
                "done\n"
                "\n"
                "echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter 2> /dev/null\n"
                "echo \""<<localPortRangeStart<<" "<<localPortRangeEnd<<"\" > /proc/sys/net/ipv4/ip_local_port_range 2> /dev/null\n"
                "\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Configuring firewall rules.")<<"\"\n"
                "# Set up our logging and packet 'executing' chains\n";

            // Rate limited logging rules.
            // The drop rule first.
            stream<<"iptables -N logdrop2\n";
            if(logdrop) {
                stream<<"iptables -A logdrop2 -j LOG --log-prefix \"DROPPED \" --log-level "<<loglevel<<" ";
                if(logipoptions) {
                    stream<<"--log-ip-options ";
                }
                if(logtcpoptions) {
                    stream<<"--log-tcp-options ";
                }
                if(logtcpsequence) {
                    stream<<"--log-tcp-sequence ";
                }
                stream<<"\n";
            }
            stream<<"iptables -A logdrop2 -j DROP\n";
            stream<<"iptables -N logdrop\n";
            if(logdrop && logratelimit) 
            {
                stream<<"iptables -A logdrop -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logdrop2\n";
                if(logwarnlimit) 
                {
                    stream<<"iptables -A logdrop -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
                }
                stream<<"iptables -A logdrop -j DROP\n";
            } 
            else 
            {
                stream<<"iptables -A logdrop -j logdrop2\n";
            }

            // Packet rejecting rules & more logging.
            stream<<"iptables -N logreject2\n";
            if(logreject) 
            {
                stream<<"iptables -A logreject2 -j LOG --log-prefix \"REJECTED \" --log-level "<<loglevel<<" ";
                if(logipoptions) 
                {
                    stream<<"--log-ip-options ";
                }
                if(logtcpoptions) 
                {
                    stream<<"--log-tcp-options ";
                }
                if(logtcpsequence) 
                {
                    stream<<"--log-tcp-sequence ";
                }
                stream<<"\n";
            }
            stream<<"iptables -A logreject2 -p tcp -j REJECT --reject-with tcp-reset\n"
                "iptables -A logreject2 -p udp -j REJECT --reject-with icmp-port-unreachable\n"
                "iptables -A logreject2 -j DROP\n";
            stream<<"iptables -N logreject\n";
            if(logreject && logratelimit) 
            {
                stream<<"iptables -A logreject -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logreject2\n";
                if(logwarnlimit) 
                {
                    stream<<"iptables -A logreject -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
                }
                stream<<"iptables -A logreject -p tcp -j REJECT --reject-with tcp-reset\n"
                    "iptables -A logreject -p udp -j REJECT --reject-with icmp-port-unreachable\n"
                    "iptables -A logreject -j DROP\n";
            } 
            else 
            {
                stream<<"iptables -A logreject -j logreject2\n";
            }

            // Logging Aborted TCP.
            if(logabortedtcp) 
            {
                stream<<"iptables -N logaborted2\n"
                    "iptables -A logaborted2 -j LOG --log-prefix \"ABORTED \" --log-level "<<loglevel<<" ";
                if(logipoptions) 
                {
                    stream<<"--log-ip-options ";
                }
                if(logtcpoptions) 
                {
                    stream<<"--log-tcp-options ";
                }
                if(logtcpsequence) 
                {
                    stream<<"--log-tcp-sequence ";
                }
                stream<<"\n";
                // Put this rule here so that we don't return from this chain
                // and interfer with any Rate Limit warnings.
                stream<<"iptables -A logaborted2 -m state --state ESTABLISHED,RELATED -j ACCEPT\n";

                stream<<"iptables -N logaborted\n";
                if(logratelimit) 
                {
                    stream<<"iptables -A logaborted -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logaborted2\n";
                    if(logwarnlimit) 
                    {
                        stream<<"iptables -A logaborted -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
                    }
                } 
                else 
                {
                    stream<<"iptables -A logaborted -j logaborted2\n";
                }
            }

            stream<<"\n"
                "# Allow loopback traffic.\n"
                "iptables -A INPUT -i lo -j ACCEPT\n"
                "iptables -A OUTPUT -o lo -j ACCEPT\n";

            if(dhcpcenabled) 
            {
                std::vector< std::string > dhcpclientinterfaces;
                boost::split(dhcpclientinterfaces, dhcpcinterfacename, boost::is_any_of(", "), boost::token_compress_on);
                //                                QStringList dhcpclientinterfaces = QStringList::split(std::string(","),dhcpcinterfacename);
                stream << "\n"
                    "# Allow DHCP clients.\n";
                BOOST_FOREACH( std::string const & i, dhcpclientinterfaces )
                {
                    stream << "iptables -A INPUT -i "<< i <<" -p udp --dport 68 --sport 67 -j ACCEPT\n"
                        "iptables -A OUTPUT -o " << i <<" -p udp --dport 67 --sport 68 -j ACCEPT\n";
                }
            }

            if(dhcpdenabled) 
            {
                std::vector< std::string > dhcpserverinterfaces;
                boost::split(dhcpserverinterfaces, dhcpdinterfacename, boost::is_any_of(", "), boost::token_compress_on);
                //                                QStringList dhcpserverinterfaces = QStringList::split(std::string(","),dhcpdinterfacename);
                stream<<"\n"
                    "# Allow DHCP servers.\n";
                BOOST_FOREACH( std::string const & i, dhcpserverinterfaces )
                {
                    stream << "iptables -A INPUT -i " << i << " -p udp --dport 67 --sport 68 -j ACCEPT\n"
                        "iptables -A OUTPUT -o " << i << " -p udp --dport 68 --sport 67 -j ACCEPT\n";
                }
            }

            stream<<"\n"
                "# Switch the current language for a moment\n"
                "GUARDDOG_BACKUP_LANG=$LANG\n"
                "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
                "LANG=US\n"
                "LC_ALL=US\n"
                "export LANG\n"
                "export LC_ALL\n"
                "# Accept broadcasts from ourself.\n"
                "IP_BCAST_PAIRS=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",$1)}\n"
                "/inet addr:.*Bcast/ {match($0,/inet addr:[[:digit:]\\\\.]+/)\n"
                "ip=substr($0,RSTART+10,RLENGTH-10)\n"
                "match($0,/Bcast:[[:digit:]\\\\.]+/)\n"
                "bcast = substr($0,RSTART+6,RLENGTH-6)\n"
                "printf \\\"%s_%s_%s\\\\n\\\",nic,ip,bcast }'`\"\n"

                "# Restore the language setting\n"
                "LANG=$GUARDDOG_BACKUP_LANG\n"
                "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
                "export LANG\n"
                "export LC_ALL\n"

                "for X in $IP_BCAST_PAIRS ; do\n"
                "  NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
                "  IP=\"`echo \\\"$X\\\" | cut -f 2 -d _`\"\n"
                "  BCAST=\"`echo \\\"$X\\\" | cut -f 3 -d _`\"\n"
                "  iptables -A INPUT -i $NIC -s $IP -d $BCAST -j ACCEPT\n"
                "done\n"
                "\n";

            // Detect and log aborted TCP connections.
            if ( logabortedtcp ) 
            {
                stream<<"# Detect aborted TCP connections.\n"
                    "iptables -A INPUT -m state --state ESTABLISHED,RELATED -p tcp --tcp-flags RST RST -j logaborted\n";
            }

            // Allow ESTABLISHED and RELATED packets.
            stream<<"# Quickly allow anything that belongs to an already established connection.\n"
                "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                "\n"
                "# Allow certain critical ICMP types\n"
                "iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT  # Dest unreachable\n"
                "iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT # Dest unreachable\n"
                "iptables -A FORWARD -p icmp --icmp-type destination-unreachable -j ACCEPT &> /dev/null  # Dest unreachable\n"
                "iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT            # Time exceeded\n"
                "iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT           # Time exceeded\n"
                "iptables -A FORWARD -p icmp --icmp-type time-exceeded -j ACCEPT &> /dev/null # Time exceeded\n"
                "iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT        # Parameter Problem\n"
                "iptables -A OUTPUT -p icmp --icmp-type parameter-problem -j ACCEPT       # Parameter Problem\n"
                "iptables -A FORWARD -p icmp --icmp-type parameter-problem -j ACCEPT &> /dev/null # Parameter Problem\n"
                "\n"

                "# Switch the current language for a moment\n"
                "GUARDDOG_BACKUP_LANG=$LANG\n"
                "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
                "LANG=US\n"
                "LC_ALL=US\n"
                "export LANG\n"
                "export LC_ALL\n"

                "# Work out our local IPs.\n"

                // This is insane. The amount of escaping.
                // The gawk program to be executed looks like this:
                //
                //      /^\w/ { nic = gensub(/^(.*):.*/,"\\1","g",$1)}
                //      /inet addr:/ { match($0,/inet addr:[[:digit:]\.]+/)
                //      printf "%s_%s\n",nic,substr($0,RSTART+10,RLENGTH-10) }
                //      /Bcast/ { match($0,/Bcast:[[:digit:]\.]+/)
                //      printf "%s_%s\n",nic,substr($0,RSTART+6,RLENGTH-6) }
                //
                // Now escape to put it in quotes for the shell:
                //
                //      NIC_IP="`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\"\\\\1\",\"g\",\$1)}
                //      /inet addr:/ { match(\$0,/inet addr:[[:digit:]\\.]+/)
                //      printf \"%s_%s\\n\", nic,substr(\$0,RSTART+10,RLENGTH-10) }
                //      /Bcast/ { match(\$0,/Bcast:[[:digit:]\\.]+/)
                //      printf \"%s_%s\\n\", nic,substr(\$0,RSTART+6,RLENGTH-6) }'`"
                //
                // Now we escape it again for the C compilier.

                "NIC_IP=\"`ifconfig | gawk '/^\\w/ { nic = gensub(/^(.*):.*/,\\\"\\\\\\\\1\\\",\\\"g\\\",\\$1)}\n"
                "/inet addr:/ { match(\\$0,/inet addr:[[:digit:]\\\\.]+/)\n"
                "printf \\\"%s_%s\\\\n\\\",nic,substr(\\$0,RSTART+10,RLENGTH-10) }\n"
                "/Bcast/ { match(\\$0,/Bcast:[[:digit:]\\\\.]+/)\n"
                "printf \\\"%s_%s\\\\n\\\",nic,substr(\\$0,RSTART+6,RLENGTH-6) }'`\"\n"

                "# Restore the language setting\n"
                "LANG=$GUARDDOG_BACKUP_LANG\n"
                "LC_ALL=$GUARDDOG_BACKUP_LC_ALL\n"
                "export LANG\n"
                "export LC_ALL\n"

                "# Create the nicfilt chain\n"
                "iptables -N nicfilt\n"
                "GOT_LO=0\n"
                "NIC_COUNT=0\n"
                "for X in $NIC_IP ; do\n"
                "    NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
                "    iptables -A nicfilt -i $NIC -j RETURN\n"
                "    # We also take this opportunity to see if we only have a lo interface.\n"
                "    if [ $NIC == \"lo\" ]; then\n"
                "        GOT_LO=1\n"
                "    fi\n"
                "    let NIC_COUNT=$NIC_COUNT+1\n"
                "done\n"
                "IPS=\"`echo \\\"$NIC_IP\\\" | cut -f 2 -d _`\"\n"
                "iptables -A nicfilt -j logdrop\n"
                "# Do we have just a lo interface?\n"
                "if [ $GOT_LO -eq 1 ] && [ $NIC_COUNT -eq 1 ] ; then\n"
                "  MIN_MODE=1\n"
                "else\n"
                "  MIN_MODE=0\n"
                "fi\n"
                "# Are there *any* interfaces?\n"
                "if [ $NIC_COUNT -eq 0 ] ; then\n"
                "  MIN_MODE=1\n"
                "fi\n"
                "# If we only have a lo interface or no interfaces then we assume that DNS\n"
                "# is not going to work and just skip any iptables calls that need DNS.\n";

            // Create the filter chains.
            stream<<"\n# Create the filter chains\n";
            // 'From' zone loop
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                // 'To' zone loop
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( zit != zit2 ) 
                    {
                        // Create the fitler chain for this combinatin of source and dest zone.
                        stream << "# Create chain to filter traffic going from '" << zit.getName() <<"' to '" << zit2.getName() << "'\n";
                        stream << "iptables -N f" << zit.getId() << "to" << zit2.getId() << "\n";
                    }
                }
            }

            // This PortRangeInfo object holds the info about the super tight
            // port ranges our machine now uses.
            localPRI.dynamicStart = localPortRangeStart;
            localPRI.dynamicEnd = localPortRangeEnd;

            // Now we add the rules to the filter chains.
            stream<<"# Add rules to the filter chains\n";
            // 'From' zone loop
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                // 'To' zone loop
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( zit != zit2 ) 
                    {
                        // Detect and accept permitted protocols.
                        std::vector< std::string > permitZoneProtocols = getConnectedZoneProtocols( zit.getName(), zit2.getName(), Zone::PERMIT );
                        stream<<"\n# Traffic from '"<< zit.getName() << "' to '"<< zit2.getName() << "'\n";
                        BOOST_FOREACH( std::string const & zoneProtocol, permitZoneProtocols )
                        {
                            stream << "# Allow '" << zoneProtocol <<"'\n";
                            std::vector< ProtocolNetUse > networkuses = getNetworkUse( zoneProtocol );

                            BOOST_FOREACH( ProtocolNetUse & networkuse, networkuses )
                            {
                                // If this netuse has been marked with the RELATED pragma
                                // then we don't need to output it becuase netfilter will
                                // be connection tracking it. The general state handling
                                // rule will handle this connection automatically.

                                if ( !networkuse.description.empty() ) 
                                {
                                    stream <<"# "<< networkuse.description << "\n";
                                }
                                if ( networkuse.pragma[ "guarddog" ] != "RELATED" )
                                {
                                    if ( networkuse.source==ENTITY_CLIENT) 
                                    {
                                        expandIPTablesFilterRule(stream,zit.getId(),zit.getId()==localindex ? &localPRI : 0, zit2.getId(),zit2.getId()==localindex ? &localPRI : 0,networkuse);
                                    }
                                    if ( networkuse.dest==ENTITY_CLIENT) 
                                    {
                                        expandIPTablesFilterRule(stream,zit2.getId(),zit2.getId()==localindex ? &localPRI : 0, zit.getId(),zit.getId()==localindex ? &localPRI : 0, networkuse);
                                    }
                                } 
                                else 
                                {
                                    stream<<"#  - Handled by netfilter state tracking\n";
                                }
                            }
                        }

                        // Detect and reject protocols that have been marked for such treatment. :-)

                        std::vector< std::string > rejectZoneProtocols = getConnectedZoneProtocols( zit.getName(), zit2.getName(), Zone::REJECT );
                        stream<<"\n# Rejected traffic from '"<<zit.getName()<<"' to '"<<zit2.getName()<<"'\n";
                        BOOST_FOREACH( std::string const & zoneProtocol, rejectZoneProtocols )
                        {
                            stream << "# Reject '" << zoneProtocol << "'\n";

                            std::vector< ProtocolNetUse > networkuses = getNetworkUse( zoneProtocol );

                            BOOST_FOREACH( ProtocolNetUse & networkuse, networkuses )
                            {
                                if ( networkuse.description.length() != 0 ) 
                                {
                                    stream<<"# "<<networkuse.description <<"\n";
                                }
                                if(networkuse.source==ENTITY_CLIENT) 
                                {
                                    expandIPTablesFilterRule(stream,zit.getId(),zit.getId()==localindex ? &localPRI : 0, zit2.getId(),zit2.getId()==localindex ? &localPRI : 0,networkuse,false,logreject);
                                }
                                if(networkuse.dest==ENTITY_CLIENT) 
                                {
                                    expandIPTablesFilterRule(stream,zit2.getId(),zit2.getId()==localindex ? &localPRI : 0, zit.getId(),zit.getId()==localindex ? &localPRI : 0,networkuse,false,logreject);
                                }
                            }
                        }
                    }
                }
            }

            // Place DENY and log rules at the end of our filter chains
            stream<<"\n"
                "# Place DROP and log rules at the end of our filter chains.\n";
            // 'From' zone loop
            BOOST_FOREACH( Zone & zit, zones ) 
            {
                // 'To' zone loop
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( zit != zit2 ) 
                    {
                        // Finally, the DENY and LOG packet rule to finish things off.
                        stream<<"# Failing all the rules above, we log and DROP the packet.\n"
                            "iptables -A f" << zit.getId() << "to" << zit2.getId() << " -j logdrop\n";
                    }
                }
            }

            // Temporarily enable DNS lookups
            stream<<"\n"
                "# Add some temp DNS accept rules to the input and output chains.\n"
                "# This is so that we can pass domain names to ipchains and have iptables be\n"
                "# able to look it up without being blocked by our half-complete firewall.\n"
                "if [ $MIN_MODE -eq 0 ] ; then\n"
                "  iptables -A OUTPUT -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
                "  iptables -A INPUT -p tcp ! --syn --sport 53:53 --dport 0:65535 -j ACCEPT\n"
                "  iptables -A OUTPUT -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
                "  iptables -A INPUT -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
                "fi\n";

            // Create the split chains.

            BOOST_FOREACH( Zone & zit, zones ) 
            {
                stream<<"\n# Chain to split traffic coming from zone '" << zit.getName() <<"' by dest zone\n";
                stream<<"iptables -N s" << zit.getId() <<"\n";

                // Fill the chain.
                // Branch for traffic going to the Local zone.
                if ( !zit.isLocal() )
                {
                    stream<<"for X in $IPS ; do\n"
                        "    iptables -A s"<<zit.getId() <<" -d $X -j f"<<zit.getId() <<"to"<<localindex<<"\n"
                        "done\n";
                }

                stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";

                // Branch for traffic going to every other chain
                for(int mask=32; mask>=0; mask--) 
                {
                    BOOST_FOREACH( Zone & zit2, zones ) 
                    {
                        if ( zit != zit2 && !zit2.isLocal() && !zit2.isInternet()) 
                        {
//                            zoneptr = zit2->current();
//                            for(addy=zoneptr->membermachine.first(); addy!=0; addy=zoneptr->membermachine.next()) 
                            BOOST_FOREACH( IPRange const & addy, zit2.getMemberMachineList() ) 
                            {
                                if ( addy.getMask()==(uint)mask) 
                                {
                                    stream<<"iptables -A s" << zit.getId() <<" -d "<<addy.getAddress()<<" -j f" << zit.getId() << "to" << zit2.getId() <<"\n";
                                }
                            }
                        }
                    }
                }
                stream<<"    true # make sure this if [] has at least something in it.\n"
                    "fi\n";

                // Add "catch all" rules for internet packets
                if ( !zit.isInternet() ) 
                {  // Except for the chain that handles traffic coming from the internet.
                    stream<<"iptables -A s" << zit.getId() <<" -j f" << zit.getId() << "to" << internetindex<<"\n";
                } 
                else 
                {
                    // We should not see traffic coming from the internet trying to go directly back
                    // out to the internet. That's weird, and worth logging.
                    stream<<"iptables -A s"<< zit.getId() << " -j logdrop\n";
                }
            }

            // Create and fill the scrfilt chain.
            stream<<"# Create the srcfilt chain\n"
                "iptables -N srcfilt\n";
            stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";
            for(int mask=32; mask>=0; mask--) 
            {
                BOOST_FOREACH( Zone & zit2, zones ) 
                {
                    if ( !zit2.isLocal() && !zit2.isInternet()) 
                    {
                        BOOST_FOREACH( IPRange const & addy, zit2.getMemberMachineList() ) 
                        {
                            if(addy.getMask() == (uint)mask) 
                            {
                                stream<<"iptables -A srcfilt -s " << addy.getAddress()<<" -j s"<<zit2.getId()<<"\n";
                            }
                        }
                    }
                }
            }

            stream<<"    true # make sure this if [] has at least something in it.\n"
                "fi\n";

            stream<<"# Assume internet default rule\n"
                "iptables -A srcfilt -j s"<<internetindex<<"\n"
                "\n";

            // Remove the temp DNS accept rules.
            stream<<"if [ $MIN_MODE -eq 0 ] ; then\n"
                "  # Remove the temp DNS accept rules\n"
                "  iptables -D OUTPUT -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
                "  iptables -D INPUT -p tcp ! --syn --sport 53:53 --dport 0:65535 -j ACCEPT\n"
                "  iptables -D OUTPUT -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
                "  iptables -D INPUT -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
                "fi\n"
                "\n"
                "# The output chain is very simple. We direct everything to the\n"
                "# 'source is local' split chain.\n"
                "iptables -A OUTPUT -j s"<<localindex<<"\n"
                "\n"
                "iptables -A INPUT -j nicfilt\n"
                "iptables -A INPUT -j srcfilt\n"
                "\n"
                "# All traffic on the forward chains goes to the srcfilt chain.\n"
                "iptables -A FORWARD -j srcfilt &> /dev/null\n"
                "\n"
                "logger -p auth.info -t guarddog Finished configuring firewall\n"
                "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Finished.")<<"\"\n";

        }

        ///////////////////////////////////////////////////////////////////////////
        //
        // permit==true && log==true is not supported.
        //
        void expandIPTablesFilterRule(std::ostream & stream, int fromzone, PortRangeInfo *fromzonePRI, int tozone, PortRangeInfo *tozonePRI,
                ProtocolNetUse const & netuse, bool permit = true, bool log = false) 
        {
            const char *icmpname;

            // Source and dest ports specified. Each source port spec <-> dest port
            // spec needs to be covered. Basically a cartesian product of the two
            // lists. In reality, this should be rare, fortunately.
            switch(netuse.type) 
            {
                case IPPROTO_TCP:
                    BOOST_FOREACH( ProtocolNetUseDetail const & source, netuse.sourceDetails() )
                    {
                        BOOST_FOREACH( ProtocolNetUseDetail const & dest, netuse.destDetails() )
                        {
                            stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<" -p tcp"
                                " --sport "<<(source.getStart(fromzonePRI))<<":"<<(source.getEnd(fromzonePRI))<<
                                " --dport "<<(dest.getStart(tozonePRI))<<":"<<(dest.getEnd(tozonePRI))<<
                                " -m state --state NEW";
                            if(permit) {
                                // Permitted
                                stream<<" -j ACCEPT\n";
                            } else {
                                // Not permitted.
                                if(log) {
                                    stream<<" -j logreject\n";
                                } else {
                                    stream<<" -j REJECT --reject-with tcp-reset\n";
                                }
                            }
                        }
                    }
                    break;

                case IPPROTO_UDP:
                    BOOST_FOREACH( ProtocolNetUseDetail const & source, netuse.sourceDetails() )
                    {
                        BOOST_FOREACH( ProtocolNetUseDetail const & dest, netuse.destDetails() )
                        {
                            stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<" -p udp"
                                " --sport "<<(source.getStart(fromzonePRI))<<":"<<(source.getEnd(fromzonePRI))<<
                                " --dport "<<(dest.getStart(tozonePRI))<<":"<<(dest.getEnd(tozonePRI));
                            if(permit) {
                                // Permitted.
                                stream<<" -j ACCEPT\n";
                            } else {
                                // Not permitted.
                                if(log) {
                                    stream<<" -j logreject\n";
                                } else {
                                    stream<<" -j REJECT --reject-with icmp-port-unreachable\n";
                                }
                            }
                            /*
                            // We do *not* actually add this rule below, like we need to in the ipchains code.
                            // We rely on connection tracking to handle return packets. Actually, this code
                            // below is a security flaw.
                            if(netuse.bidirectional) {
                            stream<<"iptables -A f"<<tozone<<"to"<<fromzone<<" -p udp"
                            " --sport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI))<<
                            " --dport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI));
                            if(permit) {
                            // Permitted.
                            stream<<" -j ACCEPT\n";
                            } else {
                            // Not permitted.
                            if(log) {
                            stream<<" -j logreject\n";
                            } else {
                            stream<<" -j REJECT --reject-with icmp-port-unreachable\n";
                            }
                            }
                            }
                             */                    
                        }
                    }        
                    break;

                case IPPROTO_ICMP:
                    BOOST_FOREACH( ProtocolNetUseDetail const & source, netuse.sourceDetails() )
                    {
                        // Map the type/code into a name that iptables can understand.
                        // Actuall this isn't strictly neccessary, but it does make the
                        // generated much easier for people to read and audit.
                        switch(source.getType()) {
                            case 0:
                                icmpname = "echo-reply";
                                break;
                            case 3:
                                icmpname = "destination-unreachable";
                                switch(source.getCode()) {
                                    case 0: icmpname = "network-unreachable"; break;
                                    case 1: icmpname = "host-unreachable"; break;
                                    case 2: icmpname = "protocol-unreachable"; break;
                                    case 3: icmpname = "port-unreachable"; break;
                                    case 4: icmpname = "fragmentation-needed"; break;
                                    case 5: icmpname = "source-route-failed"; break;
                                    case 6: icmpname = "network-unknown"; break;
                                    case 7: icmpname = "host-unknown"; break;
                                    case 9: icmpname = "network-prohibited"; break;
                                    case 10: icmpname = "host-prohibited"; break;
                                    case 11: icmpname = "TOS-network-unreachable"; break;
                                    case 12: icmpname = "TOS-host-unreachable"; break;
                                    case 13: icmpname = "communication-prohibited"; break;
                                    case 14: icmpname = "host-precedence-violation"; break;
                                    case 15: icmpname = "precedence-cutoff"; break;
                                    default: break;
                                }
                                break;
                            case 4:
                                icmpname = "source-quench";
                                break;
                            case 5:
                                icmpname = "redirect";
                                switch(source.getCode()) {
                                    case 0: icmpname = "network-redirect"; break;
                                    case 1: icmpname = "host-redirect"; break;
                                    case 2: icmpname = "TOS-network-redirect"; break;
                                    case 3: icmpname = "TOS-host-redirect"; break;
                                    default: break;
                                }
                                break;
                            case 8:
                                icmpname = "echo-request";
                                break;
                            case 9:
                                icmpname = "router-advertisement";
                                break;
                            case 10:
                                icmpname = "router-solicitation";
                                break;
                            case 11:
                                icmpname = "time-exceeded";
                                switch(source.getCode()) {
                                    case 0: icmpname = "ttl-zero-during-transit"; break;
                                    case 1: icmpname = "ttl-zero-during-reassembly"; break;
                                    default: break;
                                }
                                break;
                            case 12:
                                icmpname = "parameter-problem";
                                switch(source.getCode()) {
                                    case 0: icmpname = "ip-header-bad"; break;
                                    case 1: icmpname = "required-option-missing"; break;
                                    default: break;
                                }
                                break;
                            case 13:
                                icmpname = "timestamp-request";
                                break;
                            case 14:
                                icmpname = "timestamp-reply";
                                break;
                            case 17:
                                icmpname = "address-mask-request";
                                break;
                            case 18:
                                icmpname = "address-mask-reply";
                                break;
                            default:
                                icmpname = 0;
                                break;
                        }

                        stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<" -p icmp --icmp-type ";
                        if(icmpname!=0) {
                            stream<<(icmpname);
                        } else {
                            stream<<(source.getType());
                            if(source.getCode()!=-1) {
                                stream<<"/"<<(source.getCode());
                            }
                        }

                        if(permit) {
                            // Permitted.
                            stream<<" -j ACCEPT\n";
                        } else {
                            // Not permitted.
                            if(log) {
                                stream<<" -j logreject\n";
                            } else {
                                stream<<" -j DROP\n";   // We can't REJECT icmp really. But
                                // we can't just ACCEPT it either.
                            }
                        }
                    }
                    break;

                default:    // Every other protocol.
                    if(permit) 
                    {
                        stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<
                            " -p "<<netuse.getType()<<
                            " -j ACCEPT\n";
                        // Unlike the ipchains code, we don't need to check for
                        // bidirectionness. We can just relay on connection tracking
                        // to handle that.
                    }
                    break;        
            }
        }

        bool readFirewall(std::istream & stream,std::string &errorstring) 
        {
            std::cout << "readFirewall" << std::endl;
            std::string s;
            std::vector<Zone>::iterator zit;
            std::vector<Zone>::const_iterator zit2;
            int state;
#define READSTATE_FIRSTLINE 0
#define READSTATE_SECONDLINE 1
#define READSTATE_COPPERPLATE   2
#define READSTATE_DESCRIPTION   3
#define READSTATE_CONFIG    4
#define READSTATE_ZONECONFIG    5
#define READSTATE_USERDEFINEDPROTOCOL 6
#define READSTATE_PROTOCOLCONFIG    7
            //    bool ok;
            uint udpid;
            uchar udptype;
            uint udpstartport;
            uint udpendport;
            bool udpbidirectional;
            std::string parameterlist[] = {
                "# LOCALPORTRANGESTART=",
                "# LOCALPORTRANGEEND=",
                "# DISABLED=",
                "# LOGREJECT=",
                "# LOGDROP=",
                "# LOGABORTEDTCP=",
                "# LOGIPOPTIONS=",
                "# LOGTCPOPTIONS=",
                "# LOGTCPSEQUENCE=",
                "# LOGLEVEL=",
                "# LOGRATELIMIT=",
                "# LOGRATE=",
                "# LOGRATEUNIT=",
                "# LOGRATEBURST=",
                "# LOGWARNLIMIT=",
                "# LOGWARNRATE=",
                "# LOGWARNRATEUNIT=",
                "# DHCPC=",
                "# DHCPCINTERFACENAME=",
                "# DHCPD=",
                "# DHCPDINTERFACENAME=",
                "# ALLOWTCPTIMESTAMPS=",
            };
            uint i;
            std::string rightpart;
            bool addcr;

            //    errorstring = (const char *)0;
            state = READSTATE_FIRSTLINE;

            //    stream.setEncoding(QTextStream::Latin1);

            //    s = stream.readLine();
            std::getline( stream, s );
            if(s.empty()) goto error;

            state = READSTATE_SECONDLINE;
            //    s = stream.readLine();
            std::getline( stream, s );
            if(s.empty()) goto error;

            if(s=="## [GuardDog]") {
                errorstring = "Sorry, old Guarddog firewall files can not be read.";
                goto error;
            } else if(s!="# [Guarddog2]") {
                errorstring = ("Error reading firewall file. This does not appear to be a Guarddog firewall file.");
                goto error;
            }    

            // Read past the boring human readable copperplate stuff.
            state = READSTATE_COPPERPLATE;
            while(true) {
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s=="# [Config]") {   // Config is starting, goodie, lets break this.
                    state = READSTATE_CONFIG;
                    break;
                }
                if(s=="# [Description]") {
                    state = READSTATE_DESCRIPTION;
                    break;
                }
            }

            // Read the firewall description.
            description = "";
            addcr = false;
            if(state==READSTATE_DESCRIPTION) {
                while(true) {
                    //            s = stream.readLine();
                    std::getline( stream, s );
                    if(s.empty()) goto error;
                    if(s=="# [Config]") {
                        state = READSTATE_CONFIG;
                        break;
                    }
                    if(addcr==true) {
                        description.append("\n");
                    }
                    addcr = true;
                    description += (s.substr(3));
                }
            }

            state = READSTATE_CONFIG;
            while(true) {
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr(0,3) == ("# [")) {
                    break;  // We've got to the end of this part of the show.
                }
                // Try to identify the line we are looking at.
                //BTS
                for(i=0; i < 22 /*parameterlist.size()*/; i++) {
                    if(s.substr(0, parameterlist[i].size() ) == (parameterlist[i])) {
                        break;
                    }
                }
                if(i < 22 /*parameterlist.size()*/ ) {
                    rightpart = s.substr(parameterlist[i].size());
                    switch(i) {
                        case 0:     // # LOCALPORTRANGESTART=
                            std::cout << "i = " << i << " rightpart = " << rightpart << " s = " << s << std::endl;
                            localPortRangeStart = boost::lexical_cast<uint>( rightpart ); //.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOCALPORTRANGESTART section.");
                            //                    goto error;
                            //                }
                            if(localPortRangeStart<1024) {
                                errorstring = ("Value in LOCALPORTRANGESTART section was less then 1024.");
                                goto error;
                            }
                            break;
                        case 1:     // # LOCALPORTRANGEEND=
                            localPortRangeEnd = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOCALPORTRANGEEND section.");
                            //                    goto error;
                            //                }
                            if(localPortRangeEnd>65535) {
                                errorstring = ("Value in LOCALPORTRANGEEND is greater than 65535.");
                                goto error;
                            }
                            break;
                        case 2:     // # DISABLED=
                            disabled = rightpart=="1";
                            break;
                        case 3:     // # LOGREJECT=
                            logreject = rightpart=="1";
                            break;
                        case 4:     // # LOGDROP=
                            logdrop = rightpart=="1";
                            break;
                        case 5:     // # LOGABORTEDTCP=
                            logabortedtcp = rightpart=="1";
                            break;
                        case 6:     // # LOGIPOPTIONS=
                            logipoptions = rightpart=="1";
                            break;
                        case 7:     // # LOGTCPOPTIONS=
                            logtcpoptions = rightpart=="1";
                            break;
                        case 8:     // # LOGTCPSEQUENCE=
                            logtcpsequence = rightpart=="1";
                            break;
                        case 9:     // # LOGLEVEL=",
                            loglevel = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGLEVEL section.");
                            //                    goto error;
                            //                }
                            if(loglevel>7) {
                                errorstring = ("Error, the value in the LOGLEVEL section is too big.");
                                goto error;
                            }
                            break;
                        case 10:     // # LOGRATELIMIT=
                            logratelimit = rightpart=="1";
                            break;
                        case 11:    // # LOGRATE=
                            lograte = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGRATE section.");
                            //                    goto error;
                            //                }
                            if(lograte>65535) {
                                errorstring = ("Error, the value in the LOGRATE section is too big (>65535).");
                                goto error;
                            }
                            break;
                        case 12:    // # LOGRATEUNIT=
                            lograteunit = (LogRateUnit)boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGRATEUNIT section.");
                            //                    goto error;
                            //                }
                            if(lograteunit>3) {
                                errorstring = ("Error the value in the LOGRATEUNIT section is out of range.");
                                goto error;
                            }
                            break;
                        case 13:    // # LOGRATEBURST=
                            lograteburst = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGRATEBURST section.");
                            //                    goto error;
                            //                }
                            if(lograteburst > 65535) {
                                errorstring = ("Error, the value in the LOGRATEBURST section is too big.");
                                goto error;
                            }
                            break;
                        case 14:    // # LOGWARNLIMIT=
                            logwarnlimit = rightpart=="1";
                            break;
                        case 15:    // # LOGWARNRATE=
                            logwarnrate = boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGWARNRATE section.");
                            //                    goto error;
                            //                }
                            if(logwarnrate > 65535) {
                                errorstring = ("Error, the value in the LOGWARNRATE section is too big (>65535).");
                                goto error;
                            }
                            break;
                        case 16:    // # LOGWARNRATEUNIT=
                            logwarnrateunit = (LogRateUnit)boost::lexical_cast<uint>( rightpart ); //rightpart.toUInt(&ok);
                            //                if(ok==false) {
                            //                    errorstring = ("Error parsing the value in the LOGWARNRATEUNIT section.");
                            //                    goto error;
                            //                }
                            if(logwarnrateunit>3) {
                                errorstring = ("Error the value in the LOGWARNRATEUNIT section is out of range.");
                                goto error;
                            }
                            break;
                        case 17:    // # DHCPC=
                            dhcpcenabled = rightpart=="1";
                            break;
                        case 18:    // # DHCPCINTERFACENAME=
                            dhcpcinterfacename = rightpart;
                            break;
                        case 19:    // # DHCPD=
                            dhcpdenabled = rightpart=="1";
                            break;
                        case 20:    // # DHCPDINTERFACENAME=
                            dhcpdinterfacename = rightpart;
                            break;
                        case 21:    // # ALLOWTCPTIMESTAMPS=
                            allowtcptimestamps = rightpart=="1";
                            break;

                        default:
                            // Should we complain?
                            break;
                    }
                }
            }

            // Sanity check these values.
            if(localPortRangeEnd<localPortRangeStart) {
                errorstring = ("Value for LOCALPORTRANGEEND is less than the one in LOCALPORTRANGESTART");
                goto error;
            }

            state = READSTATE_ZONECONFIG;

            // Parse a Zone record.
            while( s =="# [Zone]") 
            {
                std::cout << "Got a zone record line" << std::endl;
                Zone newzone(Zone::UserZone);

                // Parse the Zone name.
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr( 0, 7) != ("# NAME=")) {
                    errorstring = ("Error parsing firewall [Zone] section. Expected '# NAME='");
                    goto error;
                }
                newzone.setName( s.substr(7) );  // strlen("# NAME=")==7

                // Parse the Zone comment.
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr(0,10) != ("# COMMENT=")) {
                    errorstring = ("Error parsing firewall [Zone] section. Expected '# COMMENT='");
                    goto error;
                }
                newzone.setComment( s.substr(10) );  // strlen("# COMMENT=") == 10

                // Parse the Zone addresses.
                while(true) 
                {
                    //            s = stream.readLine();
                    std::getline( stream, s );
                    if(s.empty()) goto error;
                    if(s.substr(0,10) == ("# ADDRESS=")) 
                    {
                        std::cout << "...adding address... " << s.substr(10) << std::endl;
                        newzone.addMemberMachine(IPRange(s.substr(10))); // strlen("# ADDRESS=") == 10
                    } 
                    else 
                    {
                        std::cout << "Pushing the zone" << std::endl;
                        zones.push_back(newzone);
                        break;
                    }
                }
            }

            // Read in any user defined protocols.
            state = READSTATE_USERDEFINEDPROTOCOL;
            while(s=="# [UserDefinedProtocol]") 
            {
                // Snarf the ID.
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr(0,5) != ("# ID=")) 
                {
                    errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# ID='");
                    goto error;
                }
                std::cout << "S = " << s << std::endl;
                udpid = boost::lexical_cast<uint>( s.substr(5)); //.toUInt(); // strlen("# ID=") == 5

                // Snarf the NAME
                //        s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr(0,7) != ("# NAME=")) 
                {
                    errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# NAME='");
                    goto error;
                }
                std::string tmpstring = s.substr(7); // strlen("# NAME=") == 7

                // Snarf the protocol type.
                //s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s=="# TYPE=TCP") 
                {
                    udptype = IPPROTO_TCP;
                } 
                else 
                {
                    if(s=="# TYPE=UDP") 
                    {
                        udptype = IPPROTO_UDP;
                    } 
                    else 
                    {
                        errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# TYPE=TCP' or '# TYPE=UDP'");
                        goto error;
                    }
                }

                // Snarf the PORT now.
                //s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s.substr(0,7) != ("# PORT=")) 
                {
                    errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# PORT='");
                    goto error;
                }

                // # PORT=xxx:yyy
                // or for compatebility
                // # PORT=xxx
                //
                // if the colon is missing, it's file from an older version
                if (s.find(":") == std::string::npos) 
                {
                    udpstartport = udpendport = boost::lexical_cast<uint>(s.substr(7)); //.toUInt();
                } 
                else 
                {
                    std::cout << " s: " << s << std::endl;
                    std::cout << "s1: " << s.substr( 7, s.find(":")-7 ) << std::endl;
                    std::cout << "s2: " << s.substr( s.find(":")+1 ) << std::endl;
                    udpstartport = boost::lexical_cast<uint>(s.substr(7, s.find(":")-7)); //.toUInt(); // strlen("# PORT=") == 7
                    udpendport = boost::lexical_cast<uint>(s.substr(s.find(":")+1));//.toUInt();
                }

                // Bidirectional or not?
                //s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
                if(s=="# BIDIRECTIONAL=0") 
                {
                    udpbidirectional = false;
                } 
                else 
                {
                    if(s=="# BIDIRECTIONAL=1") 
                    {
                        udpbidirectional = true;
                    } 
                    else 
                    {
                        errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# BIDIRECTIONAL=0' or '# BIDIRECTIONAL=1'");
                        goto error;
                    }
                }

                // Create and fill in the new User Defined Protocol object.
                UserDefinedProtocol udp(tmpstring, udptype, udpstartport, udpendport, udpbidirectional, pdb, udpid);
//                udp.setName(tmpstring);
//                udp.setType((uchar)udptype);
//                udp.setStartPort(udpstartport);
//                udp.setEndPort(udpendport);
//                udp.setBidirectional(udpbidirectional);

                userdefinedprotocols.push_back( udp );

                //s = stream.readLine();
                std::getline( stream, s );
                if(s.empty()) goto error;
            }

            state = READSTATE_PROTOCOLCONFIG;

            zit = zones.begin();
            zit2 = zones.begin();
            // Parse the protocol info.
            while(true) 
            {
                if(s.substr(0,14) == ("# [ServerZone]")) 
                {
                    zit2 = zones.begin();

                    //s = stream.readLine();
                    std::getline( stream, s );
                    if(s.empty()) goto error;

                    while(true) 
                    {
                        if(zit2 == zit ) 
                        {
                            ++zit2;
                        }
                        if(s.substr(0,14) == ("# [ClientZone]")) 
                        {
                            //s = stream.readLine();
                            std::getline( stream, s );
                            if(s.empty()) goto error;

                            if(s.substr(0,13) == ("# CONNECTED=1")) 
                            {
                                updateZoneConnection( zit->getName(), zit2->getName(), true );

                                while(true) 
                                {
                                    //s = stream.readLine();
                                    std::getline( stream, s );
                                    if(s.empty()) goto error;

                                    if(s.substr(0,11) == ("# PROTOCOL=")) 
                                    {
                                        try
                                        {
                                            ProtocolEntry & pe = pdb.lookup(s.substr(11));
                                            zit->setProtocolState(*zit2,pe,Zone::PERMIT);
                                        }
                                        catch ( ... )
                                        {
                                            std::cout << "Shouldn't see this anymore..." << std::endl;
                                            ProtocolEntry pe( s.substr(11) );
                                            pdb.addProtocolEntry( pe );
                                            zit->setProtocolState(*zit2,pe,Zone::PERMIT);
                                        }
                                    } 
                                    else 
                                    {
                                        if(s.substr(0,9) == ("# REJECT=")) 
                                        {
                                            try
                                            {
                                                ProtocolEntry & pe = pdb.lookup(s.substr(9));
                                                zit->setProtocolState(*zit2,pe,Zone::REJECT);
                                            }
                                            catch ( ... )
                                            {
                                            std::cout << "Shouldn't see this anymore..." << std::endl;
                                                ProtocolEntry pe( s.substr(11) );
                                                pdb.addProtocolEntry( pe );
                                                zit->setProtocolState(*zit2,pe,Zone::PERMIT);
                                            }

                                        } 
                                        else 
                                        {
                                            break;
                                        }
                                    }
                                }
                            } else {
                                // This zone is disconnected.
                                if(s.substr(0,13) != ("# CONNECTED=0")) {
                                    errorstring = ("Error parsing firewall [ServerZone] section. Expected '# CONNECTED=0' or '# CONNECTED=1'");
                                    goto error;
                                }
                                zit->disconnect(zit2->getName());
                                //s = stream.readLine();  // take us to the next line.
                                std::getline( stream, s );
                                if(s.empty()) goto error;
                            }
                            ++zit2;  // Take us to the next client zone in anticipation.
                        } 
                        else 
                        {
                            ++zit;
                            break;
                        }
                    }
                } else if(s.substr(0,7) == ("# [End]")) {
                    break;
                } else {
                    goto error;
                }
            }
            //    delete zit2;
            //    delete zit;
            //    zit = 0;
            //    zit2 = 0;
            return true;

error:
            if(errorstring.empty()) {
                switch(state) {
                    case READSTATE_FIRSTLINE:
                        errorstring = ("Error reading first line of firewall.");
                        break;

                    case READSTATE_SECONDLINE:
                        errorstring = ("Error reading second line of firewall. Expected [Guarddog2]");
                        break;

                    case READSTATE_COPPERPLATE:
                        errorstring = ("Error reading file. (Before [Config] section.)");
                        break;

                    case READSTATE_CONFIG:
                        errorstring = ("Error reading file. ([Config] section.)");
                        break;


                    case READSTATE_ZONECONFIG:
                        errorstring = ("Error reading firewall. (In the Zone config).");
                        break;

                    case READSTATE_PROTOCOLCONFIG:
                        errorstring = ("Error reading firewall. (In the Protocol config).");
                        break;

                    default:
                        errorstring = ("Unknown error.");
                        break;
                }
            }
            //    delete zit2;
            //    delete zit;

            return false;
        }

        ///////////////////////////////////////////////////////////////////////////
        bool openFirewall(const std::string &filename,std::string &errorstring) {
            std::cout << "openFirewall" << std::endl;
            std::ifstream in( filename.c_str() );

            if ( !in )
            {
                errorstring = ("Unable to open the firewall from reading.");
                return false;
            }
            return readFirewall(in, errorstring);
        }

        ///////////////////////////////////////////////////////////////////////////
        void clearFirewall() 
        {
            zones.clear();
        }

        ///////////////////////////////////////////////////////////////////////////
        void factoryDefaults() 
        {
            std::cout << "factoryDefaults()" << std::endl;

            clearFirewall();
            disabled = false;
            logreject = true;

            // Default Internet Zone.
            Zone inetzone(Zone::InternetZone);
            inetzone.setName( "Internet" );
            inetzone.setComment("Internet/Default Zone [built in]");
            zones.push_back(inetzone);

            // Default Local Machine Zone.
            Zone localzone(Zone::LocalZone);
            localzone.setName( "Local" );
            localzone.setComment("Local Machine zone [built in]");
            zones.push_back(localzone);

            updateZoneConnection( inetzone.getName(), localzone.getName(), true );
            updateZoneConnection( localzone.getName(), inetzone.getName(), true );

            localPortRangeStart = 1024;
            localPortRangeEnd = 5999;

            logdrop = true;
            logreject = true;
            logabortedtcp = true;
            logipoptions = true;
            logtcpoptions = true;
            logtcpsequence = true;
            loglevel = LOG_WARNING;
            logratelimit = true;
            lograte = 1;
            lograteunit = SECOND;
            lograteburst = 10;
            logwarnlimit = true;
            logwarnrate = 2;
            logwarnrateunit = MINUTE;
            dhcpcenabled = false;
            dhcpcinterfacename = "eth0";
            dhcpdenabled = false;
            dhcpdinterfacename = "eth0";
            allowtcptimestamps = false;

            description = "";
        }

        ///////////////////////////////////////////////////////////////////////////
        void saveFirewall(const std::string &filename ) 
        {
            std::ofstream f( filename.c_str() );
            writeFirewall( f );
            //chmod 0700 ?
        }

        bool runFirewall(const std::string &filename )
        {
            std::string command;

            command = filename;
            command += ";read -p \"Press return to continue\"";
            // From the command line this cunstruct looks something like:
            // /usr/bin/konsole -nowelcome -caption "Guarddog: Starting Firewall" -e /bin/bash -c "rc.firewall;read -p \"Press return to continue\""

            system( command.c_str() );
            return true;
        }

        bool applyFirewall()
        {
#if 0
            KTempFile tmpfile(0,0,0700);
            tmpfile.setAutoDelete(true);
            if(tmpfile.status()!=0) {
                errorstring = ("An error occurred while applying the firewall.\nThe operating system has this to report about the error: %1")
                    .arg(strerror(tmpfile.status()));
                return false;
            }

            if(writeFirewall(*(tmpfile.textStream()),errorstring)==false) {
                return false;
            }
            if(!tmpfile.close()) {
                errorstring = ("An error occurred while applying the firewall.\nThe operating system has this to report about the error: %1")
                    .arg(strerror(tmpfile.status()));
                return false;
            }

            return runFirewall(tmpfile.name(), errorstring);
#endif
            return false;
        }

        ///////////////////////////////////////////////////////////////////////////
        //
        // This simples removes any firewall that maybe current in force on the system.
        //
        bool resetSystemFirewall()
        {

            std::string command;

            command = "FILTERSYS=0\n"
                "if [ -e /sbin/ipchains ]; then\n"
                "FILTERSYS=1\n"
                "fi;\n"
                "if [ -e /proc/sys/kernel/osrelease ]; then\n"
                "  if [ `sed \"s/^\\([0-9][0-9]*\\.[0-9][0-9]*\\).*\\$/\\1/\" < /proc/sys/kernel/osrelease` == \"2.4\" ]; then\n"
                "    if [ -e /sbin/iptables ]; then\n"
                "      FILTERSYS=2\n"
                "    fi;\n"
                "  fi;\n"
                "fi;\n"
                "if [ $FILTERSYS -eq 0 ]; then\n"
                "  /usr/bin/logger -p auth.info -t guarddog \"ERROR Can't determine the firewall command! (Is ipchains or iptables installed?)\"\n"
                "fi;\n"
                "if [ $FILTERSYS -eq 2 ]; then\n"
                "/sbin/iptables -P OUTPUT ACCEPT\n"
                "/sbin/iptables -P INPUT ACCEPT\n"
                "/sbin/iptables -P FORWARD ACCEPT\n"
                "/sbin/iptables -F FORWARD\n"
                "/sbin/iptables -F INPUT\n"
                "/sbin/iptables -F OUTPUT\n"
                "fi;\n"
                "read -p \"Press return to continue\"\n";

            system( command.c_str() );
            return true;
        }

    };


