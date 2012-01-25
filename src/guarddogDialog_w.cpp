#include "guarddogDialog_w.h"
#include "guarddogAboutDialog_w.h"
#include <iostream>

void GuardDogFireWall::buildGUI() 
{
    if ( gui != 0 )
        gui->rebuildGui();
}


void GuardDogDialog_w::on_aboutPushButton_clicked()
{
    GuardDogAboutDialog_w aboutDialog;
    aboutDialog.exec();
#if 0
    QDialog aboutData("guarddog",I18N_NOOP("Guarddog"),VERSION,
        I18N_NOOP("Firewall utility"),KAboutData::License_GPL,
        "(c) 2000-2007, Simon Edwards",
        I18N_NOOP("Utility for easily creating and configuring a firewall."),
        "http://www.simonzone.com/software/guarddog/");

    aboutData.addAuthor("Simon Edwards",I18N_NOOP("Developer"),"simon@simonzone.com","http://www.simonzone.com/");
    aboutData.addCredit("J F Gratton",I18N_NOOP("Help with a little bit of network code."));
    aboutData.addCredit("Joerg Buchland",I18N_NOOP("Help with sorting out what /dev interface ISDN uses."));
    aboutData.addCredit("Ludovic Lange",I18N_NOOP("Bug fixes, DHCP help."));
    aboutData.addCredit("Jason L. Buberel",I18N_NOOP("Feedback, protocol info."));
    aboutData.addCredit("Carsten Pfeiffer",I18N_NOOP("Feedback, help with KDE3"));
    aboutData.addCredit("Gunner Poulsen", I18N_NOOP("Danish translation"));
    aboutData.addCredit("Daniele Medri", I18N_NOOP("Italian translation"));
    aboutData.addCredit("Stephan Johach", I18N_NOOP("German translation"));
    aboutData.addCredit("Pascal Billery Schneider", I18N_NOOP("French translation"));
    aboutData.addCredit("Ceoldo Costantino", I18N_NOOP("Italian translation"));
    aboutData.addCredit("Per Agerb�", I18N_NOOP("Code Contribution"));
    aboutData.addCredit("Antonio Diaz", I18N_NOOP("Spanish translation"));
    aboutData.addCredit("Tomas N?mec", I18N_NOOP("Czech translation"));
    aboutData.addCredit("Ray Lambert", I18N_NOOP("Port reference tab"));
#endif
}

///////////////////////////////////////////////////////////////////////////
void GuardDogDialog_w::on_okayPushButton_clicked() {
    firewall.save();
}

void GuardDogDialog_w::on_cancelPushButton_clicked() {
    if (firewall.cancel() )
        close();
}

void GuardDogDialog_w::on_applyPushButton_clicked() 
{
//    firewall.apply();


//  Move this to the firewall apply
#if 0
	QString errorstring;
    QString filename(SYSTEM_RC_FIREWALL);
    
    if(firewall.saveFirewall(filename,errorstring)==false) {
		QMessageBox::critical(0,"TITLE3", QObject::tr("An error occurred while writing the firewall script to disk.\n\n"
            "(Detailed message: \"%1\")").arg(errorstring));
		return;
	}
    if(applyFirewall(true)) 
    {
        modified = false;
    }
#endif
}


void GuardDogDialog_w::rebuildGui()
{
    if ( guiReady )
    {
//    updatinggui = true;
        zoneListWidget->clear();
        std::vector< std::string > zones = firewall.getZoneList();
        BOOST_FOREACH( std::string const & s, zones )
        {
            zoneListWidget->addItem( QString( s.c_str() ) );
            std::cout << "zones: " << s << std::endl;
        }
        zoneListWidget->setCurrentRow( 0 );

        buildConnectionGUI();

//        zit->toFirst();
        if ( firewall.zoneCount() > 0 )
        {
            setZoneGUI( firewall.currentZone() );
            setZoneAddressGUI( firewall.currentZone() );
            setZoneConnectionGUI( firewall.currentZone() );
        }
//        setUserDefinedProtocolGUI( UserDefinedProtocol const & userprotocol) 

        // Put the widgets in the right state for the logging page.
        logDroppedPacketsCheckBox->setChecked(firewall.isLogDrop());
        logRejectPacketsCheckBox->setChecked(firewall.isLogReject());
        logAbortedTcpCheckBox->setChecked(firewall.isLogAbortedTCP());
        logIpOptionsCheckBox->setChecked(firewall.isLogIPOptions());
        logTcpSequenceCheckBox->setChecked(firewall.isLogTCPSequence());
        logTcpOptionsCheckBox->setChecked(firewall.isLogTCPOptions());
        logLevelComboBox->setCurrentIndex(firewall.getLogLevel());
        logUserRateLimitCheckBox->setChecked(firewall.isLogRateLimit());

        logRateSpinBox->setValue(firewall.getLogRate());

        logRateUnitComboBox->setCurrentIndex(firewall.getLogRateUnit());
        logBurstSpinBox->setValue(firewall.getLogRateBurst());
        logWarnRateLimitCheckBox->setChecked(firewall.isLogWarnLimit());
        logWarnRateLimitSpinBox->setValue(firewall.getLogWarnLimitRate());
        logWarnRateUnitComboBox->setCurrentIndex(firewall.getLogWarnLimitRateUnit());

        // Put the widgets in the right state for the Advanced page.
        uint start, end;
        firewall.getLocalDynamicPortRange(start,end);
        localPortRangeLowSpinBox->setValue(start);
        localPortRangeHighSpinBox->setValue(end);

        disableFirewallCheckBox->setChecked(firewall.isDisabled());

        enableDhcpCheckBox->setChecked(firewall.isDHCPcEnabled());
        dhcpInterfaceNameLineEdit->setText(firewall.getDHCPcInterfaceName().c_str());
        
        enableDhcpdCheckBox->setChecked(firewall.isDHCPdEnabled());
        dhcpdInterfaceNameLineEdit->setText(firewall.getDHCPdInterfaceName().c_str());

        allowTcpTimeStampsCheckBox->setChecked(firewall.isAllowTCPTimestamps());
    
        // Add each User Defined Protocol to the list box.
        std::vector< UserDefinedProtocol > const & udp = firewall.getUserDefinedProtocols();

        BOOST_FOREACH( UserDefinedProtocol const & u, udp )
        {
            userDefinedProtocolTableWidget->insertRow( userDefinedProtocolTableWidget->rowCount() );
            userDefinedProtocolTableWidget->setItem( userDefinedProtocolTableWidget->rowCount()-1, 0, new QTableWidgetItem( u.getName().c_str() ) );
            userDefinedProtocolTableWidget->setItem( userDefinedProtocolTableWidget->rowCount()-1, 1, new QTableWidgetItem( u.getType()==IPPROTO_TCP ? QObject::tr("TCP") : QObject::tr("UDP") ) );
            userDefinedProtocolTableWidget->setItem( userDefinedProtocolTableWidget->rowCount()-1, 2, new QTableWidgetItem( u.getRangeString().c_str() ) );
        }


//        udpit = firewall.newUserDefinedProtocolsIterator();
//        for(; udpit->current(); ++(*udpit)) {
//            addUserDefinedProtocolToListBox(udpit->current());
//        }
        createProtocolPages();
        setProtocolPagesEnabled(!firewall.isDisabled());
        setAdvancedPageEnabled(!firewall.isDisabled());
        if ( firewall.zoneCount() > 0 )
            setZonePageEnabled(firewall.currentZone(), !firewall.isDisabled());
        setLoggingPageEnabled(!firewall.isDisabled());

        descriptionEdit->setText(firewall.description.c_str());

//        updatinggui = false;

#if 0
    QListIterator<GuardDogFirewall::Zone> *zit;
    uint start,end;
    QListIterator<UserDefinedProtocol> *udpit;

    updatinggui = true;
    
    zit = firewall.newZonesIterator();  // Select the first zone in the list box.
        // Fill up the zone list box.
    for(zit->toFirst(); zit->current(); ++(*zit)) {
        zonelistbox->insertItem(zit->current()->name);
    }
    zonelistbox->setSelected(0,true);

    buildConnectionGUI();

    zit->toFirst();
    setZoneGUI(*zit->current());
    setZoneAddressGUI(*zit->current());
    setZoneConnectionGUI(*zit->current());
    delete zit;
    zonelistbox->setSelected(0,true);

        // Put the widgets in the right state for the logging page.
    logdroppedpacketscheckbox->setChecked(firewall.isLogDrop());
    logrejectcheckbox->setChecked(firewall.isLogReject());
    logabortedtcpcheckbox->setChecked(firewall.isLogAbortedTCP());
    logipoptionscheckbox->setChecked(firewall.isLogIPOptions());
    logtcpsequencecheckbox->setChecked(firewall.isLogTCPSequence());
    logtcpoptionscheckbox->setChecked(firewall.isLogTCPOptions());
    loglevelcombobox->setCurrentItem(firewall.getLogLevel());
    loguseratelimitcheckbox->setChecked(firewall.isLogRateLimit());

    logratespinbox->setValue(firewall.getLogRate());

    lograteunitcombobox->setCurrentItem(firewall.getLogRateUnit());
    logburstspinbox->setValue(firewall.getLogRateBurst());
    logwarnratelimitcheckbox->setChecked(firewall.isLogWarnLimit());
    logwarnratespinbox->setValue(firewall.getLogWarnLimitRate());
    logwarnrateunitcombobox->setCurrentItem(firewall.getLogWarnLimitRateUnit());

        // Put the widgets in the right state for the Advanced page.
    firewall.getLocalDynamicPortRange(start,end);
    localportrangelowspinbox->setValue(start);
    localportrangehighspinbox->setValue(end);

    disablefirewallcheckbox->setChecked(firewall.isDisabled());

    enabledhcpccheckbox->setChecked(firewall.isDHCPcEnabled());
    dhcpcinterfacenamelineedit->setText(firewall.getDHCPcInterfaceName());
    
    enabledhcpdcheckbox->setChecked(firewall.isDHCPdEnabled());
    dhcpdinterfacenamelineedit->setText(firewall.getDHCPdInterfaceName());

    allowtcptimestampscheckbox->setChecked(firewall.isAllowTCPTimestamps());
    
        // Add each User Defined Protocol to the list box.
    udpit = firewall.newUserDefinedProtocolsIterator();
    for(; udpit->current(); ++(*udpit)) {
        addUserDefinedProtocolToListBox(udpit->current());
    }
    createProtocolPages();
    setProtocolPagesEnabled(!firewall.isDisabled());
    setAdvancedPageEnabled(!firewall.isDisabled());
    setZonePageEnabled(!firewall.isDisabled());
    setLoggingPageEnabled(!firewall.isDisabled());

    descriptionedit->setText(firewall.description);

    updatinggui = false;
#endif



    }
}
void GuardDogDialog_w::setLoggingPageEnabled(bool enabled) 
{

    bool logging = firewall.isLogReject() || firewall.isLogDrop();
        // Logging and options.
    logDroppedPacketsCheckBox->setEnabled(enabled);
    logRejectPacketsCheckBox->setEnabled(enabled);
    logIpOptionsCheckBox->setEnabled(enabled && logging);
    logTcpSequenceCheckBox->setEnabled(enabled && logging);
    logTcpOptionsCheckBox->setEnabled(enabled && logging);
    logLevelComboBox->setEnabled(enabled && logging);
    logAbortedTcpCheckBox->setEnabled(enabled && logging);

        // Rate limiting.
    logUserRateLimitCheckBox->setEnabled(enabled && logging);
    bool limiting = logging && firewall.isLogRateLimit();
    logRateSpinBox->setEnabled(enabled && limiting);
    logRateUnitComboBox->setEnabled(enabled && limiting);
    logBurstSpinBox->setEnabled(enabled && limiting);
        // Limit warning.
    logWarnRateLimitCheckBox->setEnabled(enabled && limiting);
    logWarnRateLimitSpinBox->setEnabled(enabled && limiting && firewall.isLogWarnLimit());
    logWarnRateUnitComboBox->setEnabled(enabled && limiting && firewall.isLogWarnLimit());
}


///////////////////////////////////////////////////////////////////////////
void GuardDogDialog_w::setProtocolPagesEnabled(bool enabled) {
//    servingzonelistbox->setEnabled(enabled);
//    protocolwidgetstack->setEnabled(enabled);
}

void GuardDogDialog_w::createProtocolPages() 
{
#if 0
    QListIterator<GuarddogDoc::Zone> *zit;
    int i;

    zit = doc->newZonesIterator();
    for(i=0; zit->current(); ++(*zit), i++) {
        servingzonelistbox->insertItem(zit->current()->name);
        addProtocolPage(zit->current(),i);
    }
    delete zit;

    servingzonelistbox->setSelected(0,true);
    servinglabel->setText(i18n("Protocols served from zone '%1' to clients in zones:")
        .arg((doc->zoneAt(0))->name));
    protocolwidgetstack->raiseWidget(0);
#endif
}
void GuardDogDialog_w::setZoneGUI( ::Zone const & zone ) 
{
    zoneNameLineEdit->setText( zone.getName().c_str());
    zoneCommentLineEdit->setText( zone.getComment().c_str());

    if ( zone.editable() ) 
    {
        zoneNameLineEdit->setReadOnly(false);
        zoneCommentLineEdit->setReadOnly(false);
        deleteZonePushButton->setEnabled(true);
    } 
    else 
    {
        zoneNameLineEdit->setReadOnly(true);
        zoneCommentLineEdit->setReadOnly(true);
        deleteZonePushButton->setEnabled(false);
    }
}

void GuardDogDialog_w::setZoneAddressGUI( ::Zone const & zone) 
{
        // Clean out the address list box.
    zoneAddressListBox->clear();
    
    zoneAddressListBox->setEnabled( zone.editable());
    
    BOOST_FOREACH( IPRange const & it, zone.getMemberMachineList() ) {
//    for(IPRange *it = zone.membermachine.first(); it!=0; it = zone.membermachine.next()) {
        zoneAddressListBox->addItem(it.getAddress().c_str());
    }
        // Display a special message for the Local zone.
    if(zone.isLocal()) {
        zoneAddressListBox->addItem(QObject::tr("<< IP addresses on the local machine >>"));
    }
        // Display a special message for the Internet zone.
    if(zone.isInternet()) {
        zoneAddressListBox->addItem(QObject::tr("<< IP addresses not matching any zone >>"));
    }
    
    newZoneAddressPushButton->setEnabled(zone.editable());
    
    if(!zone.getMemberMachineList().empty() ) {
//        zoneAddressLineEdit->setText((zone.membermachine.at(0)).getAddress().c_str());
        zoneAddressListBox->setCurrentRow(0); //,true);
        zoneAddressListBox->setEnabled(true);
        deleteZoneAddressPushButton->setEnabled(true);
        zoneAddressLineEdit->setEnabled(true);
    } 
    else 
    {
        zoneAddressLineEdit->setText("");
        zoneAddressListBox->setEnabled(false);
        deleteZoneAddressPushButton->setEnabled(false);
        zoneAddressLineEdit->setEnabled(false);
    }
}

void GuardDogDialog_w::setZonePageEnabled(::Zone const & thisZone, bool enabled) 
{
    if ( enabled) 
    {
        newZoneAddressPushButton->setEnabled(true);
        zoneAddressListBox->setEnabled(true);
    
        newZoneAddressPushButton->setEnabled(thisZone.editable());
//        deleteZoneAddressPushButton->setEnabled(thisZone.editable());        
        
        zoneNameLineEdit->setEnabled(true);
        zoneCommentLineEdit->setEnabled(true);
        
        if(!thisZone.getMemberMachineList().empty()) {
            zoneAddressListBox->setEnabled(true);
//            deleteZoneAddressPushButton->setEnabled(true);
            zoneAddressLineEdit->setEnabled(true);
        } else {
            zoneAddressListBox->setEnabled(false);
//            deleteZoneAddressPushButton->setEnabled(false);
            zoneAddressLineEdit->setEnabled(false);
        }
            
    } 
    else 
    {
            // Disable the widgets.
        newZoneAddressPushButton->setEnabled(false);
        zoneAddressListBox->setEnabled(false);        
        zoneNameLineEdit->setEnabled(false);
        zoneCommentLineEdit->setEnabled(false);
//        deleteZoneAddressPushButton->setEnabled(false);
    
        newZoneAddressPushButton->setEnabled(false);
//        deleteZoneAddressPushButton->setEnabled(false);
        zoneAddressLineEdit->setEnabled(false);
        zoneAddressListBox->setEnabled(false);
    }
}

void GuardDogDialog_w::setZoneConnectionGUI(::Zone const & zone) 
{
    zoneConnectionTableWidget->clearContents();

    std::vector< std::string > const & zoneList = firewall.getZoneList();

    BOOST_FOREACH( std::string const & s, zoneList )
    {
        zoneConnectionTableWidget->insertRow( zoneConnectionTableWidget->rowCount() );
        QTableWidgetItem * item = new QTableWidgetItem( s.c_str() );
        item->setCheckState( Qt::Unchecked );
        zoneConnectionTableWidget->setItem( zoneConnectionTableWidget->rowCount()-1, 0, item );
    }
    
#if 0
    QListIterator<GuardDogFirewall::Zone> *zit;
    QListViewItem *kid;

    zit = firewall.newZonesIterator();
    kid = connectionslistview->firstChild();
    for(; zit->current(); ++(*zit)) {
        ASSERT(kid!=0);
        ((QCheckListItem *)kid)->setOn(zone.isConnected(zit->current()));
        ((QCheckListItem *)kid)->setEnabled(zone.isConnectionMutable(zit->current()));
        kid->repaint();
        kid = kid->nextSibling();
    }
    delete zit;
#endif
}

void GuardDogDialog_w::setUserDefinedProtocolGUI( UserDefinedProtocol const & userprotocol) 
{
        userDefinedProtocolNameLineEdit->setText(userprotocol.getName().c_str());
        userDefinedProtocolTypeComboBox->setCurrentIndex(userprotocol.getType()==IPPROTO_TCP ? 0 : 1);
        userDefinedProtocolPortStartSpinBox->setValue(userprotocol.getStartPort());
        userDefinedProtocolPortEndSpinBox->setValue(userprotocol.getEndPort());
        userDefinedProtocolBidirectionalCheckBox->setEnabled(userprotocol.getType()==IPPROTO_UDP);
        userDefinedProtocolBidirectionalCheckBox->setChecked(userprotocol.isBidirectional());
#if 0
//    it's blank...
    else {
        userdefinedprotocolnamelineedit->setText("");
        userdefinedprotocolnamelineedit->setEnabled(false);
        userdefinedprotocoltypecombobox->setCurrentItem(0);
        userdefinedprotocoltypecombobox->setEnabled(false);
        userdefinedprotocolportstartspinbox->setValue(0);
        userdefinedprotocolportstartspinbox->setEnabled(false);
        userdefinedprotocolportendspinbox->setValue(0);
        userdefinedprotocolportendspinbox->setEnabled(false);
        userdefinedprotocolbidirectionalcheckbox->setChecked(false);
        userdefinedprotocolbidirectionalcheckbox->setEnabled(false);
    }
#endif
}

void GuardDogDialog_w::setAdvancedPageEnabled(bool enabled) {

//    UserDefinedProtocol *thisudp;
//    QListViewItem *item,*ptr;
        
    localPortRangeLowSpinBox->setEnabled(enabled);
    localPortRangeHighSpinBox->setEnabled(enabled);

    std::vector< UserDefinedProtocol > const & udp = firewall.getUserDefinedProtocols();

    bool gotudps = udp.size() > 0 ;
    userDefinedProtocolTableWidget->setEnabled(enabled);
    userDefinedProtocolNameLineEdit->setEnabled(enabled && gotudps);
    newUserDefinedProtocolPushButton->setEnabled(enabled);
    deleteUserDefinedProtocolPushButton->setEnabled(enabled && gotudps);
    userDefinedProtocolTypeComboBox->setEnabled(enabled && gotudps);
    userDefinedProtocolPortStartSpinBox->setEnabled(enabled && gotudps);
    userDefinedProtocolPortEndSpinBox->setEnabled(enabled && gotudps);
    if ( gotudps ) 
    {
        BOOST_FOREACH( UserDefinedProtocol const & u, udp )
        {
            if ( u.entry.name != "userdefined4" )
                continue;
            // Work out the index of the currently selected User Protocol.
            userDefinedProtocolBidirectionalCheckBox->setEnabled(enabled && gotudps && u.getType()==IPPROTO_UDP);
            break;
        }
    } 
    else 
    {
        userDefinedProtocolBidirectionalCheckBox->setEnabled(false);
    }
    enableDhcpCheckBox->setEnabled( enabled );
    dhcpInterfaceNameLineEdit->setEnabled( firewall.isDHCPcEnabled() && enabled );
    
    enableDhcpdCheckBox->setEnabled( enabled );
    dhcpdInterfaceNameLineEdit->setEnabled( firewall.isDHCPdEnabled() && enabled );

    allowTcpTimeStampsCheckBox->setEnabled(enabled);

}

void GuardDogDialog_w::buildConnectionGUI() 
{
#if 0
    QListIterator<GuardDogFirewall::Zone> *zit;
    QCheckListItem *item;

    zit = firewall.newZonesIterator();  // Select the first zone in the list box.
        // Fill up the connection listview
    for(zit->toLast(); zit->current(); --(*zit)) {
        item = new QCheckListItem((QListView *)connectionslistview,zit->current()->name,QCheckListItem::CheckBox);
        connectiondict.insert(item,zit->current());
    }
#endif
}

/***************************************************************************
                          guarddogdoc.cpp  -  description
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

// include files for Qt
#ifndef QT_LITE
//#include <qdir.h>
//#include <qfileinfo.h>
//#include <qwidget.h>
// include files for KDE
//#include <kapp.h>
//#include <kmessagebox.h>
//#include <kprocess.h>
//#include <kglobal.h>
//#include <kstddirs.h>
//#include <klocale.h>
//#include <ksavefile.h>
//#include <ktempfile.h>
#else
    // Console version stuff.
//#include "qdir.h"
//#include "qfileinfo.h"

#endif

#include <iostream>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <string.h>

// application specific includes
#include "guarddogdoc.h"
#include "zone.h"

#include <boost/foreach.hpp>
#include <QStringList>

///////////////////////////////////////////////////////////////////////////
// DEPRECIATED
//void GuardDogFirewall::Zone::enableProtocol(GuardDogFirewall::Zone *clientzone, ProtocolDB::ProtocolEntry *proto) {
//    setProtocolState(clientzone,proto,PERMIT);
//}

///////////////////////////////////////////////////////////////////////////
// DEPRECIATED
//void GuardDogFirewall::Zone::disableProtocol(GuardDogFirewall::Zone *clientzone, ProtocolDB::ProtocolEntry *proto) {
//    setProtocolState(clientzone,proto,DENY);
//
//}

///////////////////////////////////////////////////////////////////////////
// DEPRECIATED
//void  GuardDogFirewall::Zone::disableAllProtocols(GuardDogFirewall::Zone *clientzone) {
//    denyAllProtocols(clientzone);
//}
      

///////////////////////////////////////////////////////////////////////////
// DEPRECIATED
//bool GuardDogFirewall::Zone::isProtocolEnabled(GuardDogFirewall::Zone *clientzone, ProtocolDB::ProtocolEntry *proto) {
//    return getProtocolState(clientzone,proto)==PERMIT;
//}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
//GuardDogFirewall::GuardDogFirewall(ProtocolDB & database) 
//    : pdb( database )
//{
//    zones.setAutoDelete(true);
//    userdefinedprotocols.setAutoDelete(true);
//	factoryDefaults();
//}

///////////////////////////////////////////////////////////////////////////
//GuardDogFirewall::~GuardDogFirewall() {
//    while(countUserDefinedProtocols()!=0) {
//        deleteUserDefinedProtocol(userDefinedProtocolAt(0));
//    }
//}

///////////////////////////////////////////////////////////////////////////
//void GuardDogFirewall::deleteZone(GuardDogFirewall::Zone *thiszone) {
#if 0
    QList<Zone*>::iterator zit;

    zones.find(thiszone);
    zones.take();
    
    zit = zones.begin();
    
    for(;zit->current(); ++(*zit)) {
        zit->current()->deleteZone(thiszone);
    }
    delete zit;
    delete thiszone;
#endif
//}


