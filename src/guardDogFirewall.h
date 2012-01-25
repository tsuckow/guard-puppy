#pragma once

#include "guarddogdoc.h"
#include "protocoldb.h"

#include <iostream>
#include <fstream>
#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>

#include "zone.h"

#define SYSTEM_RC_FIREWALL	"/etc/rc.firewall" 

class GuardDogDialog_w;

enum { LOG_WARNING };

class GuardDogFireWall
{
    ProtocolDB  pdb;    // The protocol database we are using.
    //    GuarddogDoc doc;    // Holds all the info about the firewall we are building.
    bool modified;
    bool waspreviousfirewall;       // True if there was a previous Guarddog firewall active/available
    // at program startup.
    bool systemfirewallmodified;    // True if the current state of the system has been modified
    // since program startup. This is needed at 'Cancel' time when
    // we need to decide if we have any 'Apply'ed changes that need
    // to be undone.

    bool superUserMode;
    GuardDogDialog_w * gui;


    enum LogRateUnit {SECOND=0, MINUTE, HOUR, DAY};



public:
    //    GuarddogDoc(ProtocolDB & database);
    //    ~GuarddogDoc();

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

    //    std::vector<Zone>::iterator newZonesIterator();
    //    Zone *zoneAt(int index);
    void deleteZone(Zone *thiszone);

    std::string description;

    Zone const & currentZone( std::string const & name = "" ) const
    {
        return zones[0];
    }

private:
    //    ProtocolDB & pdb;
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
    std::vector< UserDefinedProtocol > const & getUserDefinedProtocols() const
    {
        return userdefinedprotocols;
    }
    GuardDogFireWall( bool superuser, GuardDogDialog_w * _gui = 0 )
        : pdb( "protocoldb/networkprotocoldb.xml" ), superUserMode( superuser ), gui( _gui )
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
///////////////////////////////////////////////////////////////////////////
void setDisabled(bool on) {
    disabled = on;
}

///////////////////////////////////////////////////////////////////////////
bool isDisabled() {
    return disabled;
}
///////////////////////////////////////////////////////////////////////////
void setLocalDynamicPortRange(uint start,uint end) {
    localPortRangeStart = start;
    localPortRangeEnd = end;
}

///////////////////////////////////////////////////////////////////////////
void getLocalDynamicPortRange(uint &start,uint &end) {
    start = localPortRangeStart;
    end = localPortRangeEnd;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void setDHCPcInterfaceName(const std::string &ifacename) {
    dhcpcinterfacename = ifacename;
}

///////////////////////////////////////////////////////////////////////////
std::string getDHCPcInterfaceName() {
    return dhcpcinterfacename;
}

///////////////////////////////////////////////////////////////////////////
void setDHCPdInterfaceName(const std::string &ifacename) {
    dhcpdinterfacename = ifacename;
}

///////////////////////////////////////////////////////////////////////////
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
        std::string filename(SYSTEM_RC_FIREWALL);

        if ( modified ) 
        {
            if ( saveFirewall(filename,errorstring)==false) {
                throw ( "An error occurred while writing the firewall script to disk.\n\n"
                            "(Detailed message: \"" + errorstring + "\")");
            }
            if ( applyFirewall(true)) 
            {
                saveOptions();
                //                accept();
            }
        } 
        else 
        {
            // The firewall was not modified. Just quickly exit.
            saveOptions();
            //            accept();
        }
    }

    void saveOptions() {
        //    KConfig *config;
        //    config = kapp->config();

        //    config->setGroup("General");
        //    config->writeEntry("Geometry", size());
        //    config->writeEntry("CommandrunnerGeometry",commandrunnersize);
        //    config->writeEntry("ShowAdvancedHelp",showadvancedhelp);
        //    config->sync();
    }
    ///////////////////////////////////////////////////////////////////////////
    void readOptions() {
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


    bool applyFirewall(bool warnfirst) 
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
    bool cancel() 
    {
#if 0
        std::string errorstring;

        if ( waspreviousfirewall && systemfirewallmodified) 
        {
            // This is where things become complex.
            // Should we try to restore things to how they were before this program started?
            switch(QMessageBox::question(0, "Question", 
                        ("The system's firewall settings have been modified.\n\n"
                            "Shall I restore them to the previous settings?\n\n"
                            "These changes may disrupt current network connections."), QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel, QMessageBox::Cancel )) {
                // "Yes, revert to the previous settings."
                case QMessageBox::Yes:
                    // Restore from the backup.
                    copyFile(SYSTEM_RC_FIREWALL "~", SYSTEM_RC_FIREWALL);

                    openDefault();
                    if(applyFirewall(false)) {
                        saveOptions();
                        return true;
                        //                    accept();
                    }
                    break;

                    // "Just leave the settings alone and piss off!!"
                case QMessageBox::No:
                    saveOptions();
                    return true;
                    //                accept();
                    break;

                    // "Forget I ever pressed the Cancel button."
                case QMessageBox::Cancel:
                    return false;
                    break;
                default:
                    break;
                    return false;

            }
        } 
        else 
        {
            // Simple Cancel.
            saveOptions();
            return true;
            //        accept();
        }
        #endif
        return true;
    }
    void copyFile(const char *src, const char *dest) {
        //    KProcess *proc = new KProcess();
        //    *proc<<"/bin/cp";
        //    *proc<<src<<dest;
        //    proc->start(KProcess::Block);
        //    delete proc;
    }
    void openDefault() {
        std::cout << "openDefault" << std::endl;
        std::string filename(SYSTEM_RC_FIREWALL);
        std::string errorstring;
        std::ifstream fileinfo( SYSTEM_RC_FIREWALL );

        unbuildGUI();
        if ( superUserMode==false ) 
        {
            buildGUI();
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
        buildGUI();

        // Backup the firewall.
        copyFile(SYSTEM_RC_FIREWALL,SYSTEM_RC_FIREWALL "~");
    }
    void buildGUI();
    void unbuildGUI() {
        //    updatinggui = true;
        //    zonelistbox->clear();
        //    zoneaddresslistbox->clear();
        //    unbuildConnectionGUI();
        //    userdefinedprotocolslistview->clear();
        //    deleteProtocolPages();
        //    updatinggui = false;
    }


void deleteUserDefinedProtocol(UserDefinedProtocol *thisudp) 
{
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
}
    
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

///////////////////////////////////////////////////////////////////////////

bool writeFirewall( std::ostream & stream,std::string &/*errorstring*/) {
    std::vector<Zone>::iterator zit,zit2;
    QHash<void *, ProtocolDB::ProtocolEntry *>::iterator protodictit;
//    uint i;
    int c,oldc;

    zit = zones.begin();
    zit2 = zones.begin();

//    stream.setEncoding(QTextStream::Latin1);
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
//    for(zit->toFirst(); zit->current(); ++(*zit)) {
        BOOST_FOREACH( Zone & zit, zones ) {
        if(zit.editable()) {
            stream<<"# [Zone]\n";
            stream<<"# NAME="<<(zit.getName().c_str())<<"\n";
            stream<<"# COMMENT="<<(zit.getComment())<<"\n";
            BOOST_FOREACH( IPRange const & addy, zit.getMemberMachineList() ) 
            {
//            for(addy=zit->membermachine.first(); addy!=0; addy=zit->membermachine.next()) {
                stream<<"# ADDRESS="<<addy.getAddress()<<"\n";
            }
        }
    }

        // Output the User Defined Protocols
    for(size_t i=0; i<userdefinedprotocols.size(); i++) {
        UserDefinedProtocol & currentudp = userdefinedprotocols.at(i);
        stream<<"# [UserDefinedProtocol]\n";
        stream<<"# ID="<<(currentudp.getID())<<"\n";
        stream<<"# NAME="<<(currentudp.getName())<<"\n";
        stream<<"# TYPE="<<(currentudp.getType()==IPPROTO_TCP ? "TCP" : "UDP")<<"\n";
        stream<<"# PORT="<<currentudp.getStartPort()<<":"<<currentudp.getEndPort()<<"\n";
        stream<<"# BIDIRECTIONAL="<<(currentudp.isBidirectional() ? 1 : 0)<<"\n";
    }

        // Go over each Zone and output which protocols are allowed to whom.
    BOOST_FOREACH( Zone & zit, zones ) {
//    for(zit->toFirst(); zit->current(); ++(*zit)) {
        stream<<"# [ServerZone] "<<(zit.getName().c_str())<<"\n";
        
            // Iterate over each possible client zone.
        BOOST_FOREACH( Zone & zit2, zones ) {
//        for(zit2->toFirst(); zit2->current(); ++(*zit2)) {
            if(zit != zit2) {
                stream<<"# [ClientZone] "<<(zit2.getName().c_str())<<"\n";

                if(zit.isConnected(zit2)) {
                    stream<<"# CONNECTED=1\n";
                        // Now we iterate over and output each enabled protocol.
//                    protodictit = zit.newPermitProtocolZoneIterator(zit2);
//                    if(protodictit!=0) {
//                        for(;protodictit->current(); ++(*protodictit)) {
//                            stream<<"# PROTOCOL="<<(protodictit->current()->name)<<"\n";
//                        }
//                        delete protodictit;
//                    }

                        // Output each Rejected protocol.
//                    protodictit = zit.newRejectProtocolZoneIterator(zit2);
//                    if(protodictit!=0) {
//                        for(;protodictit->current(); ++(*protodictit)) {
//                            stream<<"# REJECT="<<(protodictit->current()->name)<<"\n";
//                        }
//                        delete protodictit;
//                    }
                } else {
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
    if(disabled) {
        stream<<"DISABLE_GUARDDOG=1\n";
    } else {
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
        "if [ $FILTERSYS -eq 1 ]; then\n";
    writeIPChainsFirewall(stream);
    stream<<"fi;\n"
        "if [ $FILTERSYS -eq 2 ]; then\n";
    writeIPTablesFirewall(stream);
    stream<<"fi;\n"
        "fi;\n" // Matches the disable firewall IF.
        "true\n";

//    delete zit;
//    delete zit2;
    return true;
}

///////////////////////////////////////////////////////////////////////////
void writeIPChainsFirewall(std::ostream &stream) {
//    QList<Zone *>::iterator zit,zit2;
#if 0
    ProtocolDB::PortRangeInfo localPRI;
    uint localindex, internetindex;
    QHash<void *, ProtocolDB::ProtocolEntry *>::iterator protodictit;
    IPRange *addy;
    uint i,j;
    int mask;
    Zone *zoneptr;
    ProtocolDB::ProtocolNetUse *netuse;

    zit = zones.begin();
    zit2 = zones.begin();

    localindex = 0;
    internetindex = 0;

        // Work out what the indexes of the local zone and internet zone are.
    for(zit = zones.begin(),i=0; zit != zones.end(); ++zit,i++) {
        if((*zit)->isLocal()) {
            localindex = i;
        }
        if((*zit)->isInternet()) {
            internetindex = i;
        }
    }

    stream<<"###############################\n"
        "###### ipchains ###############\n"
        "###############################\n"
        "logger -p auth.info -t guarddog Configuring ipchains firewall now.\n"
        "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Using ipchains.")<<"\"\n"
        "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Resetting firewall rules.")<<"\"\n"
        "# Shut down all traffic\n"
        "ipchains -P forward DENY\n"
        "ipchains -P input DENY\n"
        "ipchains -P output DENY\n"
        "\n"
        "# Delete any existing chains\n"
        "ipchains -F\n"
        "ipchains -X\n"
        "\n"
        "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Setting kernel parameters.")<<"\"\n"
        "# Turn on kernel IP spoof protection\n"
        "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2> /dev/null\n"
        "# Set the up TCP timestamps config\n"
        "echo "<<(allowtcptimestamps ? "1" : "0")<<" > /proc/sys/net/ipv4/tcp_timestamps 2> /dev/null\n"
        "# Enable TCP SYN Cookie Protection\n"
        "echo 1 > /proc/sys/net/ipv4/tcp_syncookies 2> /dev/null\n"
        "echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route 2> /dev/null\n"
        "# Log truly weird packets.\n"
        "echo 1 > /proc/sys/net/ipv4/conf/all/log_martians 2> /dev/null\n"
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
        
        "echo \""<<localPortRangeStart<<" "<<localPortRangeEnd<<"\" > /proc/sys/net/ipv4/ip_local_port_range 2> /dev/null\n"
        "\n"
        "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Configuring firewall rules.")<<"\"\n"
        "# Allow loopback traffic.\n"
        "ipchains -A input -i lo -j ACCEPT\n"
        "ipchains -A output -i lo -j ACCEPT\n";
    
    if(dhcpcenabled) {
        QStringList dhcpclientinterfaces = dhcpdinterfacename.split(",");
        QStringList::Iterator it;
        stream<<"\n"
            "# Allow DHCP clients.\n";
        for(it=dhcpclientinterfaces.begin(); it!=dhcpclientinterfaces.end(); ++it) {
            stream<<
                "ipchains -A input -i " << (*it) << "  -p udp --dport 68 --sport 67 -j ACCEPT\n"
                "ipchains -A output -i " << (*it) << " -p udp --dport 67 --sport 68 -j ACCEPT\n";
        }
    }

    if(dhcpdenabled) {
        QStringList dhcpserverinterfaces = dhcpdinterfacename.split(",");
        QStringList::Iterator it;
        stream<<"\n"
            "# Allow DHCP servers.\n";
        for(it=dhcpserverinterfaces.begin(); it!=dhcpserverinterfaces.end(); ++it) {
            stream<<"ipchains -A input -i " << (*it) << " -p udp --dport 67 --sport 68 -j ACCEPT\n"
                "ipchains -A output -i " << (*it) << " -p udp --dport 68 --sport 67 -j ACCEPT\n";
        }
    }
    stream<<"\n"
        "# Accept broadcasts from ourself.\n"
        "# Switch the current language for a moment\n"
        "GUARDDOG_BACKUP_LANG=$LANG\n"
        "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
        "LANG=US\n"
        "LC_ALL=US\n"
        "export LANG\n"
        "export LC_ALL\n"
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
        "  ipchains -A input -i $NIC -s $IP -d $BCAST -j ACCEPT\n"
        "done\n"
        "\n"

        "# Allow certain critical ICMP types\n"
        "ipchains -A input -p icmp --sport 3 -j ACCEPT                 # Dest unreachable\n"
        "ipchains -A output -p icmp --sport 3 -j ACCEPT                # Dest unreachable\n"
        "ipchains -A forward -p icmp --sport 3 -j ACCEPT &> /dev/null  # Dest unreachable\n"
        "ipchains -A input -p icmp --sport 11 -j ACCEPT                # Time exceeded\n"
        "ipchains -A output -p icmp --sport 11 -j ACCEPT               # Time exceeded\n"
        "ipchains -A forward -p icmp --sport 11 -j ACCEPT &> /dev/null # Time exceeded\n"
        "ipchains -A input -p icmp --sport 12 -j ACCEPT                # Parameter Problem\n"
        "ipchains -A output -p icmp --sport 12 -j ACCEPT               # Parameter Problem\n"
        "ipchains -A forward -p icmp --sport 12 -j ACCEPT &> /dev/null # Parameter Problem\n"
        "# Work out our local IPs.\n"

            // See the iptables version of this code for more explaination.
        "# Switch the current language for a moment\n"
        "GUARDDOG_BACKUP_LANG=$LANG\n"
        "GUARDDOG_BACKUP_LC_ALL=$LC_ALL\n"
        "LANG=US\n"
        "LC_ALL=US\n"
        "export LANG\n"
        "export LC_ALL\n"
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
        "ipchains -N nicfilt\n"
        "GOT_LO=0\n"
        "NIC_COUNT=0\n"
        "for X in $NIC_IP ; do\n"
        "    NIC=\"`echo \\\"$X\\\" | cut -f 1 -d _`\"\n"
        "    IP=\"`echo \\\"$X\\\" | cut -f 2 -d _`\"\n"
        "    ipchains -A nicfilt -i $NIC -j RETURN\n"
        "    # We also take this opportunity to see if we only have a lo interface.\n"
        "    if [ $NIC == \"lo\" ]; then\n"
        "        GOT_LO=1\n"
        "    fi\n"
        "    let NIC_COUNT=$NIC_COUNT+1\n"
        "done\n"
        "IPS=\"`echo \\\"$NIC_IP\\\" | cut -f 2 -d _`\"\n"

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
        "# is not going to work and just skip any iptables calls that need DNS.\n"
        "ipchains -A nicfilt";
     if(logdrop) {
        stream<<" -l";
     }
     stream<<" -j DENY\n";

        // Create the filter chains.
    stream<<"\n# Create the filter chains\n";
        // 'From' zone loop
    BOOST_FOREACH( Zone * zit, zones ) {
//    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        BOOST_FOREACH( Zone * zit2, zones ) {
//        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit !=zit2 ) {
                    // Create the fitler chain for this combinatin of source and dest zone.
                stream<<"# Create chain to filter traffic going from '"<<(zit->name)<<"' to '"<<(zit2->name)<<"'\n";
                stream<<"ipchains -N f"<<i<<"to"<<j<<"\n";
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
    BOOST_FOREACH( Zone * zit, zones ) {
//    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        BOOST_FOREACH( Zone * zit2, zones ) {
//        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit != zit2) {
                    // Detect and accept permitted protocols.
                protodictit = zit2->newPermitProtocolZoneIterator(zit);
                stream<<"\n# Traffic from '"<<(zit->name)<<"' to '"<<(zit2->name)<<"'\n";
                if(protodictit!=0) {
                    for(;protodictit->current(); ++(*protodictit)) {
                        stream<<"# Allow '"<<(protodictit->current()->name)<<"'\n";
                        for(netuse=protodictit->networkuse.first(); netuse!=0; netuse=protodictit->networkuse.next()) {

                            if(netuse->description.length()!=0) {
                                stream<<"# "<<(netuse->description.simplifyWhiteSpace())<<"\n";
                            }
                            if(netuse->source==ProtocolDB::ENTITY_CLIENT) {
                                expandIPChainsFilterRule(stream,i,i==localindex ? &localPRI : 0,
                                    j,j==localindex ? &localPRI : 0,*netuse);
                            }
                            if(netuse->dest==ProtocolDB::ENTITY_CLIENT) {
                                expandIPChainsFilterRule(stream,j,j==localindex ? &localPRI : 0,
                                    i,i==localindex ? &localPRI : 0, *netuse);
                            }
                        }
                    }
                    delete protodictit;
                }

                    // Detect and reject protocols that have been marked for such treatment. :-)
                protodictit = zit2->current()->newRejectProtocolZoneIterator(zit->current());
                stream<<"\n# Rejected traffic from '"<<(zit->current()->name)<<"' to '"<<(zit2->current()->name)<<"'\n";
                if(protodictit!=0) {
                    for(;protodictit->current(); ++(*protodictit)) {
                        stream<<"# Reject '"<<(protodictit->current()->name)<<"'\n";
                        for(netuse=protodictit->current()->networkuse.first(); netuse!=0; netuse=protodictit->current()->networkuse.next()) {

                            if(netuse->description.length()!=0) {
                                stream<<"# "<<(netuse->description.simplifyWhiteSpace())<<"\n";
                            }
                            if(netuse->source==ProtocolDB::ENTITY_CLIENT) {
                                expandIPChainsFilterRule(stream,i,i==localindex ? &localPRI : 0,
                                    j,j==localindex ? &localPRI : 0,*netuse,false,logreject);
                            }
                            if(netuse->dest==ProtocolDB::ENTITY_CLIENT) {
                                expandIPChainsFilterRule(stream,j,j==localindex ? &localPRI : 0,
                                    i,i==localindex ? &localPRI : 0,*netuse,false,logreject);
                            }
                        }
                    }
                    delete protodictit;
                }
            }
        }
    }

        // Place DENY and log rules at the end of our filter chains
    stream<<"\n"
        "# Place DENY and log rules at the end of our filter chains.\n";
        // 'From' zone loop
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit->current()!=zit2->current()) {
                    // Finally, the DENY and LOG packet rule to finish things off.
                stream<<"# Failing all the rules above, we DENY and maybe log the packet.\n"
                    "ipchains -A f"<<i<<"to"<<j;
                if(logdrop) {
                    stream<<" -l";
                 }
                 stream<<" -j DENY\n";
            }
        }
    }

        // Temporarily enable DNS lookups
    stream<<"\n"
        "# Add some temp DNS accept rules to the input and output chains.\n"
        "# This is so that we can pass domain names to ipchains and have ipchains be\n"
        "# able to look it up without being blocked by the our half-complete firewall.\n"
        "if [ $MIN_MODE -eq 0 ] ; then\n"
        "  ipchains -A output -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  ipchains -A input -p tcp ! -y --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "  ipchains -A output -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  ipchains -A input -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "fi\n";

        // Create the split chains.
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
        stream<<"\n# Chain to split traffic coming from zone '"<<(zit->current()->name)<<"' by dest zone\n";
        stream<<"ipchains -N s"<<i<<"\n";

            // Fill the chain.
            // Branch for traffic going to the Local zone.
        if(i!=localindex) {
            stream<<"for X in $IPS ; do\n"
                "    ipchains -A s"<<i<<" -d $X -j f"<<i<<"to"<<localindex<<"\n"
                "done\n";
        }

        stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";
            // Branch for traffic going to every other chain
        for(mask=32; mask>=0; mask--) {
            for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
                if(zit->current()!=zit2->current() && !zit2->current()->isLocal() && !zit2->current()->isInternet()) {
                    zoneptr = zit2->current();
                    for(addy=zoneptr->membermachine.first(); addy!=0; addy=zoneptr->membermachine.next()) {
                        if(addy->getMask()==(uint)mask) {
                            stream<<"ipchains -A s"<<i<<" -d "<<addy->getAddress()<<" -j f"<<i<<"to"<<j<<"\n";
                        }
                    }
                }
            }
        }
        
        stream<<"true # make sure this if [] has a least something in it.\n"
            "fi\n";

            // Add "catch all" rules for internet packets
        if(i!=internetindex) {  // Except for the chain that handles traffic coming from the internet.
            stream<<"ipchains -A s"<<i<<" -j f"<<i<<"to"<<internetindex<<"\n";
        } else {
                // We should not see traffic coming from the internet trying to go directly back
                // out to the internet. That's weird, and worth logging.
            stream<<"ipchains -A s"<<i;
            if(logdrop) {
                stream<<" -l";
            }
            stream<<" -j DENY\n";
        }
    }

        // Create and fill the scrfilt chain.
    stream<<"# Create the srcfilt chain\n"
        "ipchains -N srcfilt\n"
        "if [ $MIN_MODE -eq 0 ] ; then\n";

    for(mask=32; mask>=0; mask--) {
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(!zit2->current()->isLocal() && !zit2->current()->isInternet()) {
                zoneptr = zit2->current();
                for(addy=zoneptr->membermachine.first(); addy!=0; addy=zoneptr->membermachine.next()) {
                    if(addy->getMask()==(uint)mask) {
                        stream<<"ipchains -A srcfilt -s "<<addy->getAddress()<<" -j s"<<j<<"\n";
                    }
                }
            }
        }
    }
    
    stream<<"true # make sure this if [] has a least something in it.\n"
        "fi\n"
        "# Assume internet default rule\n"
        "ipchains -A srcfilt -j s"<<internetindex<<"\n"
        "\n";

        // Remove the temp DNS accept rules.
    stream<<"# Remove the temp DNS accept rules\n"
        "if [ $MIN_MODE -eq 0 ] ; then\n"
        "  ipchains -D output -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  ipchains -D input -p tcp ! -y --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "  ipchains -D output -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  ipchains -D input -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "fi\n";

        // The input chain should siphon off traffic destined for our local machine.
    stream<<"\n"
        "# The output chain is quite simple. We diverge and filter any traffic from\n"
        "# the local machine and accept the rest. The rest should have come via the\n"
        "# forward chain, and hence is already filtered.\n"
        "ipchains -A output -j nicfilt\n"
        "for X in $IPS ; do\n"
        "    ipchains -A output -s $X -j s"<<localindex<<"\n"
        "done\n"
        "ipchains -A output -j ACCEPT\n"
        "\n"
        "ipchains -A input -j nicfilt\n"
        "# Direct local bound traffic on the input chain to the srcfilt chain\n"
        "for X in $IPS ; do\n"
        "    ipchains -A input -d $X -j srcfilt\n"
        "done\n"
        "ipchains -A input -j ACCEPT\n"
        "\n"
        "# All traffic on the forward chains goes to the srcfilt chain.\n"
        "ipchains -A forward -j nicfilt &> /dev/null\n"
        "ipchains -A forward -j srcfilt &> /dev/null\n"
        "\n"
        "logger -p auth.info -t guarddog Finished configuring firewall\n"
        "[ $GUARDDOG_VERBOSE -eq 1 ] && echo \""<<("Finished.")<<"\"\n";

//    delete zit;
//    delete zit2;
#endif
}

///////////////////////////////////////////////////////////////////////////
void expandIPChainsFilterRule(QTextStream &stream,
        int fromzone,ProtocolDB::PortRangeInfo *fromzonePRI,int tozone,ProtocolDB::PortRangeInfo *tozonePRI,
        ProtocolDB::ProtocolNetUse &netuse, bool permit = true, bool log = false ) {
#if 0
    ProtocolDB::ProtocolNetUseDetail *detailptr,*detailptr2;

        // Source and dest ports specified. Each source port spec <-> dest port
        // spec needs to be covered. Basically a cartesian product of the two
        // lists. In reality, this should be rare, fortunately.
    switch(netuse.type) {
        case IPPROTO_TCP:
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                for(detailptr2=netuse.destdetaillist.first(); detailptr2!=0; detailptr2=netuse.destdetaillist.next()) {
                    stream<<"ipchains -A f"<<fromzone<<"to"<<tozone<<" -p tcp"
                        " --sport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI))<<
                        " --dport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI));
                    if(log) {
                        stream<<" -l ";
                    }
                    if(permit) {
                        stream<<" -j ACCEPT\n";
                    } else {
                        stream<<" -j REJECT\n";
                    }
                    stream<<"ipchains -A f"<<tozone<<"to"<<fromzone<<" -p tcp ! -y"
                        " --sport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI))<<
                        " --dport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI));
                    if(log) {
                        stream<<" -l ";
                    }
                    if(permit) {
                        stream<<" -j ACCEPT\n";
                    } else {
                        stream<<" -j REJECT\n";
                    }
                }
            }
            break;

        case IPPROTO_UDP:
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                for(detailptr2=netuse.destdetaillist.first(); detailptr2!=0; detailptr2=netuse.destdetaillist.next()) {
                    stream<<"ipchains -A f"<<fromzone<<"to"<<tozone<<" -p udp"
                        " --sport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI))<<
                        " --dport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI));
                    if(log) {
                        stream<<" -l ";
                    }
                    if(permit) {
                        stream<<" -j ACCEPT\n";
                    } else {
                        stream<<" -j REJECT\n";
                    }
                    if(netuse.bidirectional) {
                        stream<<"ipchains -A f"<<tozone<<"to"<<fromzone<<" -p udp"
                            " --sport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI))<<
                            " --dport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI));
                        if(log) {
                            stream<<" -l ";
                        }
                        if(permit) {
                            stream<<" -j ACCEPT\n";
                        } else {
                            stream<<" -j REJECT\n";
                        }
                    }
                }
            }
            break;

        case IPPROTO_ICMP:
            ASSERT(netuse.sourcedetaillist.size()!=0 && netuse.destdetaillist.size()==0);
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                stream<<"ipchains -A f"<<fromzone<<"to"<<tozone<<" -p icmp --sport "<<(detailptr->type);
                if(detailptr->code!=-1) {
                    stream<<" --dport "<<(detailptr->code);
                }
                if(log) {
                    stream<<" -l ";
                }
                if(permit) {
                    stream<<" -j ACCEPT\n";
                } else {
                    stream<<" -j REJECT\n";
                }
            }
            break;

        default:    // Every other protocol
            if(permit) {
                stream<<"ipchains -A f"<<fromzone<<"to"<<tozone<<
                    " -p "<<netuse.type<<" -j ACCEPT\n";
                if(netuse.bidirectional) {
                    stream<<"ipchains -A f"<<tozone<<"to"<<fromzone<<
                        " -p "<<netuse.type<<
                        " -j ACCEPT\n";
                }
            }
            break;
    }
#endif
}

///////////////////////////////////////////////////////////////////////////
void writeIPTablesFirewall(std::ostream &stream) {
#if 0
    QList<Zone*>::iterator zit,zit2;
    ProtocolDB::PortRangeInfo localPRI;
    uint localindex, internetindex;
    QPtrDictIterator<ProtocolDB::ProtocolEntry> *protodictit;
    IPRange *addy;
    uint i,j;
    int mask;
    Zone *zoneptr;
    ProtocolDB::ProtocolNetUse *netuse;
    QStringList::Iterator pragmanameit;
    QStringList::Iterator pragmavalueit;
    QStringList::Iterator moduleit;
    bool isrelated;
    QStringList modules;
    bool gotmodule;
    const char *rateunits[] = {"second", "minute", "hour", "day" };
    zit = zones.begin();
    zit2 = zones.begin();

    localindex = 0;
    internetindex = 0;

        // Work out what the indexes of the local zone and internet zone are.
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
        if(zit->current()->isLocal()) {
            localindex = i;
        }
        if(zit->current()->isInternet()) {
            internetindex = i;
        }
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
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit->current()!=zit2->current()) {
                protodictit = zit2->current()->newPermitProtocolZoneIterator(zit->current());
                if(protodictit!=0) {
                    for(;protodictit->current(); ++(*protodictit)) {
                        pragmanameit = protodictit->current()->pragmaname.begin();
                        pragmavalueit = protodictit->current()->pragmavalue.begin();
                        for(; pragmanameit!=protodictit->current()->pragmaname.end(); ++pragmanameit) {
                            if(*pragmanameit =="guarddog") {
                                    // Only add a module to the list if we don't have it already.
                                gotmodule = false;
                                for(moduleit = modules.begin(); moduleit!=modules.end(); ++moduleit) {
                                    if(*moduleit==*pragmavalueit) {
                                        gotmodule = true;
                                        break;
                                    }
                                }
                                if(gotmodule==false) {
                                    modules.append(*pragmavalueit);
                                }
                            }
                            ++pragmavalueit;
                        }
                    }
                    delete protodictit;
                }
            }
        }
    }
        // Output the modprobe code to load the extra modules.
    for(moduleit = modules.begin(); moduleit!=modules.end(); ++moduleit) {
        stream<<"modprobe "<<(*moduleit)<<"\n";
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
    if(logdrop && logratelimit) {
        stream<<"iptables -A logdrop -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logdrop2\n";
        if(logwarnlimit) {
            stream<<"iptables -A logdrop -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
        }
        stream<<"iptables -A logdrop -j DROP\n";
    } else {
        stream<<"iptables -A logdrop -j logdrop2\n";
    }

        // Packet rejecting rules & more logging.
    stream<<"iptables -N logreject2\n";
    if(logreject) {
        stream<<"iptables -A logreject2 -j LOG --log-prefix \"REJECTED \" --log-level "<<loglevel<<" ";
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
    stream<<"iptables -A logreject2 -p tcp -j REJECT --reject-with tcp-reset\n"
        "iptables -A logreject2 -p udp -j REJECT --reject-with icmp-port-unreachable\n"
        "iptables -A logreject2 -j DROP\n";
    stream<<"iptables -N logreject\n";
    if(logreject && logratelimit) {
        stream<<"iptables -A logreject -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logreject2\n";
        if(logwarnlimit) {
            stream<<"iptables -A logreject -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
        }
        stream<<"iptables -A logreject -p tcp -j REJECT --reject-with tcp-reset\n"
            "iptables -A logreject -p udp -j REJECT --reject-with icmp-port-unreachable\n"
            "iptables -A logreject -j DROP\n";
    } else {
        stream<<"iptables -A logreject -j logreject2\n";
    }

        // Logging Aborted TCP.
    if(logabortedtcp) {
        stream<<"iptables -N logaborted2\n"
            "iptables -A logaborted2 -j LOG --log-prefix \"ABORTED \" --log-level "<<loglevel<<" ";
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
            // Put this rule here so that we don't return from this chain
            // and interfer with any Rate Limit warnings.
        stream<<"iptables -A logaborted2 -m state --state ESTABLISHED,RELATED -j ACCEPT\n";

        stream<<"iptables -N logaborted\n";
        if(logratelimit) {
            stream<<"iptables -A logaborted -m limit --limit "<<lograte<<"/"<<rateunits[lograteunit]<<" --limit-burst "<<lograteburst<<" -j logaborted2\n";
            if(logwarnlimit) {
                stream<<"iptables -A logaborted -m limit --limit "<<logwarnrate<<"/"<<rateunits[logwarnrateunit]<<" --limit-burst 1 -j LOG --log-prefix \"LIMITED \" --log-level "<<loglevel<<"\n";
            }
        } else {
            stream<<"iptables -A logaborted -j logaborted2\n";
        }
    }

    stream<<"\n"
        "# Allow loopback traffic.\n"
        "iptables -A INPUT -i lo -j ACCEPT\n"
        "iptables -A OUTPUT -o lo -j ACCEPT\n";

    if(dhcpcenabled) {
        QStringList dhcpclientinterfaces = QStringList::split(std::string(","),dhcpcinterfacename);
        QStringList::Iterator it;
        stream<<"\n"
            "# Allow DHCP clients.\n";
        for(it=dhcpclientinterfaces.begin(); it!=dhcpclientinterfaces.end(); ++it) {
            stream<<"iptables -A INPUT -i "<<(*it)<<" -p udp --dport 68 --sport 67 -j ACCEPT\n"
                "iptables -A OUTPUT -o "<<(*it)<<" -p udp --dport 67 --sport 68 -j ACCEPT\n";
        }
    }

    if(dhcpdenabled) {
        QStringList dhcpserverinterfaces = QStringList::split(std::string(","),dhcpdinterfacename);
        QStringList::Iterator it;
        stream<<"\n"
            "# Allow DHCP servers.\n";
        for(it=dhcpserverinterfaces.begin(); it!=dhcpserverinterfaces.end(); ++it) {
            stream<<"iptables -A INPUT -i "<<(*it)<<" -p udp --dport 67 --sport 68 -j ACCEPT\n"
                "iptables -A OUTPUT -o "<<(*it)<<" -p udp --dport 68 --sport 67 -j ACCEPT\n";
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
    if(logabortedtcp) {
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
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit->current()!=zit2->current()) {
                    // Create the fitler chain for this combinatin of source and dest zone.
                stream<<"# Create chain to filter traffic going from '"<<(zit->current()->name)<<"' to '"<<(zit2->current()->name)<<"'\n";
                stream<<"iptables -N f"<<i<<"to"<<j<<"\n";
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
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit->current()!=zit2->current()) {
                    // Detect and accept permitted protocols.
                protodictit = zit2->current()->newPermitProtocolZoneIterator(zit->current());
                stream<<"\n# Traffic from '"<<(zit->current()->name)<<"' to '"<<(zit2->current()->name)<<"'\n";
                if(protodictit!=0) {
                    for(;protodictit->current(); ++(*protodictit)) {
                        stream<<"# Allow '"<<(protodictit->current()->name)<<"'\n";
                        for(netuse=protodictit->current()->networkuse.first(); netuse!=0; netuse=protodictit->current()->networkuse.next()) {

                                // If this netuse has been marked with the RELATED pragma
                                // then we don't need to output it becuase netfilter will
                                // be connection tracking it. The general state handling
                                // rule will handle this connection automatically.
                            isrelated = false;
                            pragmanameit = netuse->pragmaname.begin();
                            pragmavalueit = netuse->pragmavalue.begin();
                            for(; pragmanameit!=netuse->pragmaname.end(); ++pragmanameit) {
                                if(*pragmanameit=="guarddog") {
                                    if(*pragmavalueit=="RELATED") {
                                        isrelated = true;
                                    }
                                }
                                ++pragmavalueit;
                            }

                            if(netuse->description.length()!=0) {
                                stream<<"# "<<(netuse->description.simplifyWhiteSpace())<<"\n";
                            }
                            if(isrelated==false) {
                                if(netuse->source==ProtocolDB::ENTITY_CLIENT) {
                                    expandIPTablesFilterRule(stream,i,i==localindex ? &localPRI : 0,
                                        j,j==localindex ? &localPRI : 0,*netuse);
                                }
                                if(netuse->dest==ProtocolDB::ENTITY_CLIENT) {
                                    expandIPTablesFilterRule(stream,j,j==localindex ? &localPRI : 0,
                                        i,i==localindex ? &localPRI : 0, *netuse);
                                }
                            } else {
                                stream<<"#  - Handled by netfilter state tracking\n";
                            }
                        }
                    }
                    delete protodictit;
                }

                    // Detect and reject protocols that have been marked for such treatment. :-)
                protodictit = zit2->current()->newRejectProtocolZoneIterator(zit->current());
                stream<<"\n# Rejected traffic from '"<<(zit->current()->name)<<"' to '"<<(zit2->current()->name)<<"'\n";
                if(protodictit!=0) {
                    for(;protodictit->current(); ++(*protodictit)) {
                        stream<<"# Reject '"<<(protodictit->current()->name)<<"'\n";
                        for(netuse=protodictit->current()->networkuse.first(); netuse!=0; netuse=protodictit->current()->networkuse.next()) {

                            if(netuse->description.length()!=0) {
                                stream<<"# "<<(netuse->description.simplifyWhiteSpace())<<"\n";
                            }
                            if(netuse->source==ProtocolDB::ENTITY_CLIENT) {
                                expandIPTablesFilterRule(stream,i,i==localindex ? &localPRI : 0,
                                    j,j==localindex ? &localPRI : 0,*netuse,false,logreject);
                            }
                            if(netuse->dest==ProtocolDB::ENTITY_CLIENT) {
                                expandIPTablesFilterRule(stream,j,j==localindex ? &localPRI : 0,
                                    i,i==localindex ? &localPRI : 0,*netuse,false,logreject);
                            }
                        }
                    }
                    delete protodictit;
                }
            }
        }
    }

        // Place DENY and log rules at the end of our filter chains
    stream<<"\n"
        "# Place DROP and log rules at the end of our filter chains.\n";
        // 'From' zone loop
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
            // 'To' zone loop
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(zit->current()!=zit2->current()) {
                    // Finally, the DENY and LOG packet rule to finish things off.
                stream<<"# Failing all the rules above, we log and DROP the packet.\n"
                    "iptables -A f"<<i<<"to"<<j<<" -j logdrop\n";
            }
        }
    }

        // Temporarily enable DNS lookups
    stream<<"\n"
        "# Add some temp DNS accept rules to the input and output chains.\n"
        "# This is so that we can pass domain names to ipchains and have iptables be\n"
        "# able to look it up without being blocked by the our half-complete firewall.\n"
        "if [ $MIN_MODE -eq 0 ] ; then\n"
        "  iptables -A OUTPUT -p tcp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  iptables -A INPUT -p tcp ! --syn --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "  iptables -A OUTPUT -p udp --sport 0:65535 --dport 53:53 -j ACCEPT\n"
        "  iptables -A INPUT -p udp --sport 53:53 --dport 0:65535 -j ACCEPT\n"
        "fi\n";

        // Create the split chains.
    for(zit->toFirst(),i=0; zit->current(); ++(*zit),i++) {
        stream<<"\n# Chain to split traffic coming from zone '"<<(zit->current()->name)<<"' by dest zone\n";
        stream<<"iptables -N s"<<i<<"\n";

            // Fill the chain.
            // Branch for traffic going to the Local zone.
        if(i!=localindex) {
            stream<<"for X in $IPS ; do\n"
                "    iptables -A s"<<i<<" -d $X -j f"<<i<<"to"<<localindex<<"\n"
                "done\n";
        }

        stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";

            // Branch for traffic going to every other chain
        for(mask=32; mask>=0; mask--) {
            for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
                if(zit->current()!=zit2->current() && !zit2->current()->isLocal() && !zit2->current()->isInternet()) {
                    zoneptr = zit2->current();
                    for(addy=zoneptr->membermachine.first(); addy!=0; addy=zoneptr->membermachine.next()) {
                        if(addy->getMask()==(uint)mask) {
                            stream<<"iptables -A s"<<i<<" -d "<<addy->getAddress()<<" -j f"<<i<<"to"<<j<<"\n";
                        }
                    }
                }
            }
        }
        stream<<"    true # make sure this if [] has at least something in it.\n"
            "fi\n";

            // Add "catch all" rules for internet packets
        if(i!=internetindex) {  // Except for the chain that handles traffic coming from the internet.
            stream<<"iptables -A s"<<i<<" -j f"<<i<<"to"<<internetindex<<"\n";
        } else {
                // We should not see traffic coming from the internet trying to go directly back
                // out to the internet. That's weird, and worth logging.
            stream<<"iptables -A s"<<i<<" -j logdrop\n";
        }
    }

        // Create and fill the scrfilt chain.
    stream<<"# Create the srcfilt chain\n"
        "iptables -N srcfilt\n";
    stream<<"if [ $MIN_MODE -eq 0 ] ; then\n";
    for(mask=32; mask>=0; mask--) {
        for(zit2->toFirst(),j=0; zit2->current(); ++(*zit2),j++) {
            if(!zit2->current()->isLocal() && !zit2->current()->isInternet()) {
                zoneptr = zit2->current();
                for(addy=zoneptr->membermachine.first(); addy!=0; addy=zoneptr->membermachine.next()) {
                    if(addy->getMask()==(uint)mask) {
                        stream<<"iptables -A srcfilt -s "<<addy->getAddress()<<" -j s"<<j<<"\n";
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

    delete zit;
    delete zit2;
#endif
}

///////////////////////////////////////////////////////////////////////////
//
// permit==true && log==true is not supported.
//
void expandIPTablesFilterRule(QTextStream &stream,
        int fromzone,ProtocolDB::PortRangeInfo *fromzonePRI,int tozone,ProtocolDB::PortRangeInfo *tozonePRI,
        ProtocolDB::ProtocolNetUse &netuse, bool permit = true, bool log = false) {
#if 0    
    ProtocolDB::ProtocolNetUseDetail *detailptr,*detailptr2;
    const char *icmpname;

        // Source and dest ports specified. Each source port spec <-> dest port
        // spec needs to be covered. Basically a cartesian product of the two
        // lists. In reality, this should be rare, fortunately.
    switch(netuse.type) {
        case IPPROTO_TCP:
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                for(detailptr2=netuse.destdetaillist.first(); detailptr2!=0; detailptr2=netuse.destdetaillist.next()) {
                    stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<" -p tcp"
                        " --sport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI))<<
                        " --dport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI))<<
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
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                for(detailptr2=netuse.destdetaillist.first(); detailptr2!=0; detailptr2=netuse.destdetaillist.next()) {
                    stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<" -p udp"
                        " --sport "<<(detailptr->getStart(fromzonePRI))<<":"<<(detailptr->getEnd(fromzonePRI))<<
                        " --dport "<<(detailptr2->getStart(tozonePRI))<<":"<<(detailptr2->getEnd(tozonePRI));
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
            ASSERT(netuse.sourcedetaillist.size()!=0 && netuse.destdetaillist.size()==0);
            for(detailptr=netuse.sourcedetaillist.first(); detailptr!=0; detailptr=netuse.sourcedetaillist.next()) {
                    // Map the type/code into a name that iptables can understand.
                    // Actuall this isn't strictly neccessary, but it does make the
                    // generated much easier for people to read and audit.
                switch(detailptr->type) {
                    case 0:
                        icmpname = "echo-reply";
                        break;
                    case 3:
                        icmpname = "destination-unreachable";
                        switch(detailptr->code) {
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
                        switch(detailptr->code) {
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
                        switch(detailptr->code) {
                            case 0: icmpname = "ttl-zero-during-transit"; break;
                            case 1: icmpname = "ttl-zero-during-reassembly"; break;
                            default: break;
                        }
                        break;
                    case 12:
                        icmpname = "parameter-problem";
                        switch(detailptr->code) {
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
                    stream<<(detailptr->type);
                    if(detailptr->code!=-1) {
                        stream<<"/"<<(detailptr->code);
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
            if(permit) {
                stream<<"iptables -A f"<<fromzone<<"to"<<tozone<<
                    " -p "<<netuse.type<<
                    " -j ACCEPT\n";
                    // Unlike the ipchains code, we don't need to check for
                    // bidirectionness. We can just relay on connection tracking
                    // to handle that.
            }
            break;        
    }
#endif
}

///////////////////////////////////////////////////////////////////////////
bool readFirewall(std::istream & stream,std::string &errorstring) {
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
    while(s=="# [Zone]") 
    {
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
        while(true) {
            //            s = stream.readLine();
            std::getline( stream, s );
            if(s.empty()) goto error;
            if(s.substr(0,10) == ("# ADDRESS=")) 
            {
                newzone.addMemberMachine(IPRange(s.substr(10))); // strlen("# ADDRESS=") == 10
            } 
            else 
            {
                zones.push_back(newzone);
                break;
            }
        }
    }

        // Read in any user defined protocols.
    state = READSTATE_USERDEFINEDPROTOCOL;
    while(s=="# [UserDefinedProtocol]") {
            // Snarf the ID.
//        s = stream.readLine();
    std::getline( stream, s );
        if(s.empty()) goto error;
        if(s.substr(0,5) != ("# ID=")) {
            errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# ID='");
            goto error;
        }
        std::cout << "S = " << s << std::endl;
        udpid = boost::lexical_cast<uint>( s.substr(5)); //.toUInt(); // strlen("# ID=") == 5

            // Snarf the NAME
//        s = stream.readLine();
    std::getline( stream, s );
        if(s.empty()) goto error;
        if(s.substr(0,7) != ("# NAME=")) {
            errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# NAME='");
            goto error;
        }
        std::string tmpstring = s.substr(7); // strlen("# NAME=") == 7

            // Snarf the protocol type.
        //s = stream.readLine();
    std::getline( stream, s );
        if(s.empty()) goto error;
        if(s=="# TYPE=TCP") {
            udptype = IPPROTO_TCP;
        } else {
            if(s=="# TYPE=UDP") {
                udptype = IPPROTO_UDP;
            } else {
                errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# TYPE=TCP' or '# TYPE=UDP'");
                goto error;
            }
        }

            // Snarf the PORT now.
        //s = stream.readLine();
    std::getline( stream, s );
        if(s.empty()) goto error;
        if(s.substr(0,7) != ("# PORT=")) {
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
        if(s=="# BIDIRECTIONAL=0") {
            udpbidirectional = false;
        } else {
            if(s=="# BIDIRECTIONAL=1") {
                udpbidirectional = true;
            } else {
                errorstring = ("Error parsing firewall [UserDefinedProtocol] section. Expected '# BIDIRECTIONAL=0' or '# BIDIRECTIONAL=1'");
                goto error;
            }
        }

            // Create and fill in the new User Defined Protocol object.
        UserDefinedProtocol udp(udpid);
        udp.setName(tmpstring);
        udp.setType((uchar)udptype);
        udp.setStartPort(udpstartport);
        udp.setEndPort(udpendport);
        udp.setBidirectional(udpbidirectional);

        userdefinedprotocols.push_back( udp );

        //s = stream.readLine();
    std::getline( stream, s );
        if(s.empty()) goto error;
    }

    state = READSTATE_PROTOCOLCONFIG;

    zit = zones.begin();
    zit2 = zones.begin();
        // Parse the protocol info.
    while(true) {
        if(s.substr(0,14) == ("# [ServerZone]")) {
            zit2 = zones.begin();

            //s = stream.readLine();
    std::getline( stream, s );
            if(s.empty()) goto error;

            while(true) {
                if(zit2 == zit ) {
                    ++zit2;
                }
                if(s.substr(0,14) == ("# [ClientZone]")) {
                    //s = stream.readLine();
    std::getline( stream, s );
                    if(s.empty()) goto error;

                    if(s.substr(0,13) == ("# CONNECTED=1")) {
                        zit->connect(*zit2);

                        while(true) {
                            //s = stream.readLine();
    std::getline( stream, s );
                            if(s.empty()) goto error;

                            if(s.substr(0,11) == ("# PROTOCOL=")) {
                                std::vector< ProtocolDB::ProtocolEntry >::const_iterator proto = pdb.lookup(s.substr(11));
                                if (proto != pdb.dbEnd() ) 
                                {
                                    std::cout << "...found" << std::endl;
                                    zit->setProtocolState(*zit2,*proto,Zone::PERMIT);
                                }
                            } else {
                                if(s.substr(0,9) == ("# REJECT=")) {
                                    std::vector< ProtocolDB::ProtocolEntry >::const_iterator proto = pdb.lookup(s.substr(9));
                                    if ( proto!= pdb.dbEnd() ) {
                                    std::cout << "...found" << std::endl;
                                        zit->setProtocolState(*zit2,*proto,Zone::REJECT);
                                    }
                                } else {
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
                        zit->disconnect(*zit2);
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
void clearFirewall() {
    zones.clear();
//    while(zones.size()!=0) {
//        deleteZone(zones.at(0));
//    }
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

    inetzone.connect(localzone);
    localzone.connect(inetzone);

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
bool saveFirewall(const std::string &filename, std::string &errorstring) {
#if 0
#ifndef QT_LITE    
    KSaveFile f(filename,0700);     // We want it root executable.
    
    if(f.status()!=0) {
        errorstring = ("An error occurred while writing '%1'. The operating system has this to report about the error: %2")
	    .arg(filename).arg(strerror(f.status()));
        return false;
    }
//FILE *fp = f.fstream();
//QFile *x = f.file();
    
    if(writeFirewall(*(f.textStream()), errorstring)) {
        if(f.status()!=0) {
            errorstring = ("An error occurred while writing '%1'. The operating system has this to report about the error: %2")
		    .arg(filename).arg(strerror(f.status()));
		    return false;
        }
        f.close();
        if(f.status()!=0) {
            errorstring = ("An error occurred while writing '%1'. The operating system has this to report about the error: %2")
		    .arg(filename).arg(strerror(f.status()));
		    return false;
        }
        return true;
    } else {
        f.close();
        return false;
    }
#else
    return false;
#endif
#endif
    return false;
}

/*
///////////////////////////////////////////////////////////////////////////
//
// The filename must not contain spaces or shell chars.
//
bool GuardDogFirewall::runFirewall(const std::string &filename, std::string &errorstring) {
#ifndef QT_LITE
	KProcess *proc;
	proc = new KProcess();
	std::string command;
	std::string konsolebin;

    konsolebin = locate("exe","konsole");

	command = filename;
	command += ";read -p \"Press return to continue\"";
	// From the command line this cunstruct looks something like:
	// /usr/bin/konsole -nowelcome -caption "Guarddog: Starting Firewall" -e /bin/bash -c "rc.firewall;read -p \"Press return to continue\""
	*proc << ((const char *)konsolebin) << "-nowelcome" << "-caption" << "Guarddog: Starting Firewall";
	*proc << "-e" << "/bin/bash" << "-c" << (const char *)command;

	proc->start(KProcess::Block,KProcess::NoCommunication);
		// Block, but it shoud not take long to run.
#endif
    return true;
}

///////////////////////////////////////////////////////////////////////////
bool GuardDogFirewall::applyFirewall(std::string &errorstring) {
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
}

///////////////////////////////////////////////////////////////////////////
//
// This simples removes any firewall that maybe current in force on the system.
//
bool GuardDogFirewall::resetSystemFirewall(std::string &errorstring) {
#ifndef QT_LITE
    KProcess *proc;
    std::string command;
	std::string konsolebin;

    proc = new KProcess();

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
        "if [ $FILTERSYS -eq 1 ]; then\n"
        "/sbin/ipchains -P output ACCEPT\n"
        "/sbin/ipchains -P input ACCEPT\n"
        "/sbin/ipchains -P forward ACCEPT\n"
        "/sbin/ipchains -F forward\n"
        "/sbin/ipchains -F input\n"
        "/sbin/ipchains -F output\n"
        "fi\n"
        "if [ $FILTERSYS -eq 2 ]; then\n"
        "/sbin/iptables -P OUTPUT ACCEPT\n"
        "/sbin/iptables -P INPUT ACCEPT\n"
        "/sbin/iptables -P FORWARD ACCEPT\n"
        "/sbin/iptables -F FORWARD\n"
        "/sbin/iptables -F INPUT\n"
        "/sbin/iptables -F OUTPUT\n"
        "fi;\n"
        "read -p \"Press return to continue\"\n";

qDebug(command);

    konsolebin = locate("exe","konsole");
    *proc << ((const char *)konsolebin) << "-nowelcome" << "-caption" << "Guarddog: Disabling Firewall";
    *proc << "-e" << "/bin/bash" << "-c" << command;

    proc->start(KProcess::Block,KProcess::NoCommunication);
#endif
    return true;
}
*/

};


