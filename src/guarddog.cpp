/***************************************************************************
                          guarddog.cpp  -  description
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
#include "config.h"

#include <stdlib.h>

// include files for QT
#include <qlabel.h>

#include <qdir.h>
#include <qfileinfo.h>
#include <qstrlist.h>
#include <qprinter.h>
#include <qpainter.h>
#include <qhbox.h>
#include <qgroupbox.h>
#include <qhgroupbox.h>
#include <qvgroupbox.h>
#include <qgrid.h>

// include files for KDE
#include <kiconloader.h>
#include <kmessagebox.h>
#include <kfiledialog.h>
#include <kstddirs.h>
#include <kstdaccel.h>
#include <kaction.h>
#include <kstdaction.h>
#include <klocale.h>
#include <kglobalsettings.h>
#include <unistd.h>
#include <kregexp.h>
#include <kseparator.h>
#include <ktempfile.h>

// application specific includes
#include "guarddog.h"
#include "guarddogdoc.h"
#include "commandrunner.h"

#define DEBUG_EVENTS(x) 
//qDebug(x)

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
AddressValidator::AddressValidator(QWidget *parent,const char *name) : QValidator(parent,name) {
}

///////////////////////////////////////////////////////////////////////////
AddressValidator::~AddressValidator() {
}

///////////////////////////////////////////////////////////////////////////
QValidator::State AddressValidator::validate(QString &input, int &) const {
    KRegExp sanity("^[0-9a-zA-Z./-]*$");
    KRegExp domainnametest("^([a-zA-Z][a-zA-Z0-9-]*\\.)+[a-zA-Z][a-zA-Z0-9-]*$");
    KRegExp iptest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");
    KRegExp ipmaskedtest("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)$");
    KRegExp ipmasked2test("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)/([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)$");
    long ipbyte;

    if(input.isNull()) {
        return QValidator::Intermediate;
    }

        // Smoke text
    if(sanity.match((const char *)input)==false) {
        return QValidator::Invalid;
    }
    if(input.length()==0) {
        return QValidator::Intermediate;
    }

        // Test against the domainname regexp.
    if(domainnametest.match((const char *)input)) {
        return QValidator::Acceptable;
    }

        // Ok, now lets try the IP address regexp.
    if(iptest.match((const char *)input)==true) {
        ipbyte = atol(iptest.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(iptest.group(2));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(iptest.group(3));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(iptest.group(4));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        return QValidator::Acceptable;
    }

        // Ok, now lets try the IP address regexp.
    if(ipmaskedtest.match((const char *)input)==true) {
        ipbyte = atol(ipmaskedtest.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmaskedtest.group(2));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmaskedtest.group(3));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmaskedtest.group(4));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmaskedtest.group(5));
        if(ipbyte<0 || ipbyte>32) {
            return QValidator::Intermediate;
        }
        return QValidator::Acceptable;
    }
    if(ipmasked2test.match((const char *)input)==true) {
        ipbyte = atol(ipmasked2test.group(1));    // Yep, it returns char *.
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(2));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(3));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(4));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(5));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(6));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(7));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        ipbyte = atol(ipmasked2test.group(8));
        if(ipbyte<0 || ipbyte>255) {
            return QValidator::Intermediate;
        }
        return QValidator::Acceptable;
    }
    return QValidator::Intermediate;
}

///////////////////////////////////////////////////////////////////////////
void AddressValidator::fixup(QString &input) const {
    QString clean;
    QString tmp;
    QString mask;
    uint i;
    int slashcount;
    char c;
    long ipbyte;
    KRegExp snarfnumber("^([0-9]+)");
    uint l;
    int pos;

        // This is real DWIM (Do What I Mean) code.
        // Somehow it is meant to take what the user entered and work out
        // what they meant and then correct the entered string.
        // It's just a bunch of guesses, hunches and heristics.

    if(input.isNull()) {    // Just in case.
        input = "0.0.0.0";
        return;
    }

        // Filter out any bad characters.
    clean = "";
    slashcount = 0;
    for(i=0; i<input.length(); i++) {
        c = input.at(i).latin1();
        if(c=='/') {
            if(slashcount==0) {
                clean.append('/');
                slashcount++;
            }
        } else if((c>='0' && c<='9') || c=='.' || c=='-' || (c>='A' && c<='Z') || (c>='a' && c<='z')) {
            clean.append(c);
        }
    }

    clean.replace(QRegExp("^\\.*"),QString(""));  // No dots at the start please.
    clean.replace(QRegExp("\\.*$"),QString(""));  // No dots at the end please.

        // Remove double dots.
    do {
        l = clean.length();
        clean.replace(QRegExp("\\.\\."),QString("."));
    } while(l!=clean.length());
        
        // Do we still have a string?
    if(clean.length()==0) {
        input = "0.0.0.0";  // This should not match much.
        return;
    }
        
        // Look at the first character and take a guess as to
        // what kind of value the user attempted to enter.
    if(clean.at(0).isDigit()) {
            // Ok, we expect some kind of IP address maybe with a netmask.
        clean.replace(QRegExp("[A-Za-z-]"),QString(""));   // Kill any funny chars.

        clean.replace(QRegExp("^\\.*"),QString(""));  // No dots at the start please.
        clean.replace(QRegExp("\\.*$"),QString(""));  // No dots at the end please.

            // Remove double dots.
        do {
            l = clean.length();
            clean.replace(QRegExp("\\.\\."),QString("."));
        } while(l!=clean.length());

        pos = clean.find('/');
        if(pos!=-1) {
            mask = clean.right(clean.length()-pos-1);
            clean = clean.left(pos);
        }

        i = 0;
        tmp = "";
        while(snarfnumber.match(clean) && i!=4) {
            ipbyte = atol(snarfnumber.group(1));
            if(ipbyte>255) {
                ipbyte = 255;
            }
            i++;
            tmp.append(QString::number(ipbyte));
            tmp.append(".");
            clean = clean.right(clean.length()-strlen(snarfnumber.group(1)));
            clean.replace(QRegExp("^[^0-9]*"),QString(""));
        }
        for(;i<4; i++) {
            tmp.append("0.");
        }
        tmp.replace(QRegExp("\\.$"),QString(""));

        if(mask.length()!=0) { // We still have not consumed all the input.
                                // There must be some kind of netmask left.
            if(mask.contains('.')==0) {    // It must be a single number netmask.
                tmp.append("/");
                ipbyte = mask.toLong();
                if(ipbyte>32) {
                    ipbyte = 32;
                }
                tmp.append(QString::number(ipbyte));
            } else {
                    // Expecting a dotted quad netmask.
                tmp.append("/");
                i = 0;
                while(snarfnumber.match(mask) && i!=4) {
                    ipbyte = atol(snarfnumber.group(1));
                    if(ipbyte>255) {
                        ipbyte = 255;
                    }
                    i++;
                    tmp.append(QString::number(ipbyte));
                    tmp.append(".");
                    mask = mask.right(mask.length()-strlen(snarfnumber.group(1)));
                    mask.replace(QRegExp("^[^0-9]*"),QString(""));
                }
                for(;i<4; i++) {
                    tmp.append("0.");
                }
                tmp.replace(QRegExp("\\.$"),QString(""));
            }
        }
        clean = tmp;
    
    }

    pos = 0;
    if(validate(clean, pos)!=QValidator::Acceptable) {
        input ="0.0.0.0";
    } else {
        input = clean;
    }
    return;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
InterfaceNameValidator::InterfaceNameValidator(QWidget *parent,const char *name) : QValidator(parent,name) {
}

///////////////////////////////////////////////////////////////////////////
InterfaceNameValidator::~InterfaceNameValidator() {
}

///////////////////////////////////////////////////////////////////////////
QValidator::State InterfaceNameValidator::validate(QString &input, int &) const {
    KRegExp sanity("^[0-9a-zA-Z,]*$");

    if(input.isNull()) {
        return QValidator::Intermediate;
    }
        // Smoke text
    if(sanity.match((const char *)input)==false) {
        return QValidator::Invalid;
    }
    if(input.length()==0) {
        return QValidator::Intermediate;
    }
    return QValidator::Acceptable;
}

///////////////////////////////////////////////////////////////////////////
void InterfaceNameValidator::fixup(QString &input) const {
    KRegExp sanity("^[0-9a-zA-Z,]*$");

    if(input.isNull()) {    // Just in case.
        input = "eth0";
        return;
    }
    if(input.length()==0) {
        input = "eth0";
        return;
    }
        // Sanity test
    if(sanity.match((const char *)input)==false) {
        input = "eth0";
        return;
    }
    return;
}


///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
GuarddogApp::GuarddogApp(const QString &caption) : KDialogBase(KJanusWidget::Tabbed,caption,
        KDialogBase::Help|KDialogBase::Ok|KDialogBase::Apply|KDialogBase::Cancel|KDialogBase::User1,
        KDialogBase::Ok) {
    // The real work is done in initialise().
}

///////////////////////////////////////////////////////////////////////////
bool GuarddogApp::initialise(bool god) {
    QString protocollocation;
    QHBox *t;
    QHBox *t2;
    QHBox *t3;
    QHBox *zonehorizbox;
    QHBox *protocolvertbox;
    QSplitter *protocolsplitter;
    QGrid *qgrid;
    QWidget *tmpwidget;
    QLabel *tmplabel;
    QGroupBox *tmpqgroupbox;
    KSeparator *ksep;
    superusermode = god;
    tmpwidget = 0;

    waspreviousfirewall = false;
    systemfirewallmodified = false;
    updatinggui = false;
    showadvancedhelp = false;
    pdb = 0;
    doc = 0;
    aboutus = 0;
    modified = false;
    
    if(superusermode==false) {
        enableButtonOK(false);
        enableButtonApply(false);
    }

    protocolcheckitemdicts.setAutoDelete(true);
		
		// Read in the Protocol Database.
    protocollocation = locate("data","guarddog/networkprotocoldb.xml");
    pdb = new ProtocolDB();

    if(!pdb->loadDB(protocollocation,KGlobal::locale()->languageList())) {
    	KMessageBox::error(0,i18n("An error occured while reading the protocol database.\n\nDetails: \"%1\"").arg(pdb->errorString()));
        return false;
	}

    aboutus = new KAboutApplication(this);

    setHelp("guarddog/index.html");
    setButtonText(KDialogBase::User1,i18n("About"));
    doc = new GuarddogDoc(pdb);

        // ---- Network Zones.
    zonepage = addHBoxPage(i18n("Zone"));
    zonepage->setSpacing(spacingHint());
    
    t = new QVBox(zonepage);
    zonepage->setStretchFactor(t,0);
    t->setSpacing(spacingHint());

    tmplabel = new QLabel(t);
    tmplabel->setPixmap(UserIcon("zones"));
    t->setStretchFactor(tmplabel,0);

    new QLabel(i18n("Defined Network Zones:"),t);

    zonelistbox = new KListBox(t);
    zonelistbox->setSelectionMode(QListBox::Single);
    {
    QListIterator<GuarddogDoc::Zone> *zit;
    zit = doc->newZonesIterator();
    for(; zit->current(); ++(*zit)) {
        zonelistbox->insertItem(zit->current()->name);
    }
    delete zit;
    }
    zonelistbox->setSelected(0,true);
    connect(zonelistbox,SIGNAL(clicked(QListBoxItem *)),this,SLOT(slotZoneListBox(QListBoxItem *)));
        
    newzonebutton = new QPushButton(i18n("New Zone"),t);
    connect(newzonebutton,SIGNAL(clicked()),this,SLOT(slotNewZoneButton()));
    deletezonebutton = new QPushButton(i18n("Delete Zone"),t);
    connect(deletezonebutton,SIGNAL(clicked()),this,SLOT(slotDeleteZoneButton()));

        // Zone Properties.
    tmpqgroupbox = new QVGroupBox(i18n("Zone Properties"),(QWidget *)zonepage);
    zonepage->setStretchFactor(tmpqgroupbox,1);

    zonehorizbox = new QHBox(tmpqgroupbox);
    zonehorizbox->setSpacing(spacingHint());

    t = new QVBox(zonehorizbox);
    t->setSpacing(spacingHint());

    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());

    tmplabel = new QLabel(i18n("Name: "),t2);
    t2->setStretchFactor(tmplabel,0);
    zonenamelineedit = new SimeLineEdit(t2);
    t2->setStretchFactor(zonenamelineedit,1);
    connect(zonenamelineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotZoneNameLineEdit(const QString &)));

    tmplabel = new QLabel(i18n("Comment:"),t);
    zonecommentlineedit = new SimeLineEdit(t);
    connect(zonecommentlineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotZoneCommentLineEdit(const QString &)));

        // Zone Addresses
    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Zone Addresses"),t2);
    t2->setStretchFactor(tmplabel,0);
    ksep = new KSeparator(KSeparator::HLine,t2);
    t2->setStretchFactor(ksep,1);

    zoneaddresslistbox = new KListBox(t);
    zoneaddresslistbox->setSelectionMode(QListBox::Single);
    connect(zoneaddresslistbox,SIGNAL(clicked(QListBoxItem *)),this,SLOT(slotAddressListBox(QListBoxItem *)));

    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());
    newzoneaddressbutton = new QPushButton(i18n("New Address"),t2);
    connect(newzoneaddressbutton,SIGNAL(clicked()),this,SLOT(slotNewAddressButton()));
    deletezoneaddressbutton = new QPushButton(i18n("Delete Address"),t2);
    connect(deletezoneaddressbutton,SIGNAL(clicked()),this,SLOT(slotDeleteAddressButton()));

    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Address: "),t2);
    t2->setStretchFactor(tmplabel,0);
    zoneaddresslineedit = new SimeLineEdit(t2);
    addressvalidator = new AddressValidator(zoneaddresslineedit);
    zoneaddresslineedit->setValidator(addressvalidator);
    
    t2->setStretchFactor(zoneaddresslineedit,1);
    connect(zoneaddresslineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotAddressLineEdit(const QString &)));
    connect(zoneaddresslineedit,SIGNAL(returnPressed()),this,SLOT(slotAddressLineEditReturn()));

        // Connections list
    connectionslistview  = new KListView(zonehorizbox);
    connectionslistview->setRootIsDecorated(false);
    connectionslistview->setSelectionMode(QListView::NoSelection);
    connectionslistview->setAllColumnsShowFocus(true);
    connectionslistview->setSorting(-1);   // Turn off sorting.
    connectionslistview->addColumn(i18n("Connection"));
    connect(connectionslistview,SIGNAL(clicked(QListViewItem *)),this,SLOT(slotZoneConnectionClicked(QListViewItem *)));

    tmplabel = new QLabel(i18n("Addresses can be host names, network names or IP addresses. "
        "Masks can be specified as network masks or a plain number. "
        "e.g. 192.168.1.0/255.255.255.0 or 192.168.1.0/24"),tmpqgroupbox);
    tmplabel->setAlignment(Qt::AlignLeft|Qt::WordBreak);

        // Protocols Page
    protocolpage = addHBoxPage(i18n("Protocol"));
    protocolpage->setSpacing(spacingHint());
    
    protocolsplitter = new QSplitter(protocolpage);
    protocolsplitter->setOrientation(QSplitter::Horizontal);
    
    protocolvertbox = new QVBox(protocolsplitter);
    protocolvertbox->setSpacing(spacingHint());
    protocolsplitter->setCollapsible(protocolvertbox, false);
    protocolpage->setStretchFactor(protocolvertbox,1);

        // Protocols icon
    tmplabel = new QLabel(protocolvertbox);
    tmplabel->setPixmap(UserIcon("protocols"));
    protocolvertbox->setStretchFactor(tmplabel,0);
    tmplabel = new QLabel(i18n("Defined Network Zones:"),protocolvertbox);
    // protocolvertbox->setStretchFactor(tmplabel,0);
        // Zone selector box.
    servingzonelistbox = new KListBox((QWidget *)protocolvertbox);
    protocolvertbox->setStretchFactor(servingzonelistbox,2);
    connect(servingzonelistbox,SIGNAL(clicked(QListBoxItem *)),this,SLOT(slotServedZoneListBox(QListBoxItem *)));

    protocolhelpbrowser = new KTextBrowser(protocolvertbox);
    protocolvertbox->setStretchFactor(protocolhelpbrowser,3);
    currenthelptext = i18n("<qt><p><b>Click on the name of a protocol to view information about it.</b></p>"
        "<p>(Advanced information can be turned on using the \"Show advanced protocol help\" checkbox on the Advanced tab.)</p></qt>");
    currentadvancedhelptext = currenthelptext;
    protocolhelpbrowser->setText(currenthelptext);
    
    tmpqgroupbox = new QVGroupBox(i18n("Zone Properties"),(QWidget *)protocolsplitter);
    protocolsplitter->setCollapsible(tmpqgroupbox, false);
    protocolpage->setStretchFactor(tmpqgroupbox,3);

    t = new QVBox(tmpqgroupbox);
    t->setSpacing(spacingHint());

    servinglabel = new QLabel(i18n("Protocols served from zone 'Internet' to clients in zones:"),t);
    t->setStretchFactor(servinglabel,0);

    protocolwidgetstack = new QWidgetStack(t);
    t->setStretchFactor(protocolwidgetstack,1);

    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());
    tmplabel = new QLabel(t2);
    tmplabel->setPixmap(UserIcon("box_clear"));
    t2->setStretchFactor(tmplabel,0);
    tmplabel = new QLabel(i18n("= protocol is blocked."),t2);
    t2->setStretchFactor(tmplabel,1);
    
    tmplabel = new QLabel(t2);
    tmplabel->setPixmap(UserIcon("box_checked"));
    t2->setStretchFactor(tmplabel,0);
    tmplabel = new QLabel(i18n("= protocol is permitted."),t2);
    t2->setStretchFactor(tmplabel,1);
    
    tmplabel = new QLabel(t2);
    tmplabel->setPixmap(UserIcon("box_crossed"));
    t2->setStretchFactor(tmplabel,0);
    tmplabel = new QLabel(i18n("= protocol is rejected."),t2);
    t2->setStretchFactor(tmplabel,1);

    t->setStretchFactor(t2,0);

        // Logging page.
    loggingpage = addVBoxPage(i18n("Logging"));

    t = new QHBox(loggingpage);
    t->setSpacing(spacingHint());

        // Icon.
    tmplabel = new QLabel(t);
    tmplabel->setPixmap(UserIcon("logging"));
    t->setStretchFactor(tmplabel,0);

    t2 = new QVBox(t);
    t->setStretchFactor(t2,1);

    t2->setSpacing(spacingHint());

        // Log dropped packets.
    logdroppedpacketscheckbox = new QCheckBox(i18n("Log blocked packets"),(QWidget *)t2);
    connect(logdroppedpacketscheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogDroppedPackets(bool)));
        // Log Rejected packets
    logrejectcheckbox = new QCheckBox(i18n("Log rejected packets"),(QWidget *)t2);
    connect(logrejectcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogRejectedPackets(bool)));

    tmplabel = new QLabel(i18n("Note: the options below do not apply to Linux kernels <2.4."),loggingpage);

    logabortedtcpcheckbox = new QCheckBox(i18n("Log aborted TCP connections (half open scans)"),loggingpage);
    connect(logabortedtcpcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogAbortedTCP(bool)));
    
        // Rate limiting group
    tmpqgroupbox = new QVGroupBox(i18n("Rate Limiting"),(QWidget *)loggingpage);
        // Use rate limit checkbox.
    t = new QHBox(tmpqgroupbox);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(t);
    tmplabel->setPixmap(UserIcon("rate_limit"));
    t->setStretchFactor(tmplabel,0);
    loguseratelimitcheckbox = new QCheckBox(i18n("Rate limit logging"),(QWidget *)t);
    t->setStretchFactor(loguseratelimitcheckbox,1);
    connect(loguseratelimitcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogUseRateLimit(bool)));

        // Rate input
    t = new QHBox(tmpqgroupbox);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Rate:"),t);
    t->setStretchFactor(tmplabel,0);
    logratespinbox = new KIntSpinBox(1,1000,1,1,10,t);
    connect(logratespinbox,SIGNAL(valueChanged(int)),this,SLOT(slotLogRateSpinBox(int)));

    tmplabel = new QLabel(i18n(" packets per "),t);
    t->setStretchFactor(tmplabel,0);
    lograteunitcombobox = new KComboBox((QWidget *)t);
    t->setStretchFactor(lograteunitcombobox,0);
    connect(lograteunitcombobox,SIGNAL(activated(int)),this,SLOT(slotLogRateUnitComboBox(int)));
    lograteunitcombobox->insertItem(i18n("Second"));
    lograteunitcombobox->insertItem(i18n("Minute"));
    lograteunitcombobox->insertItem(i18n("Hour"));
    lograteunitcombobox->insertItem(i18n("Day"));

        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t);
    t->setStretchFactor(tmpwidget,1);

        // Burst
    t = new QHBox(tmpqgroupbox);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Burst:"),t);
    t->setStretchFactor(tmplabel,0);
    logburstspinbox = new KIntSpinBox(1,10000,1,1,10,t);
    connect(logburstspinbox,SIGNAL(valueChanged(int)),this,SLOT(slotLogBurstSpinBox(int)));

    tmplabel = new QLabel(i18n(" packets"),t);
    t->setStretchFactor(tmplabel,0);
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t);
    t->setStretchFactor(tmpwidget,1);

        // Limiting Warn
    t = new QHBox(tmpqgroupbox);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(t);
    tmplabel->setPixmap(UserIcon("warn"));
    t->setStretchFactor(tmplabel,0);
    logwarnratelimitcheckbox = new QCheckBox(i18n("Warn when limiting"),(QWidget *)t);
    t->setStretchFactor(logwarnratelimitcheckbox,1);
    connect(logwarnratelimitcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogWarnRateLimit(bool)));

    t = new QHBox(tmpqgroupbox);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Warning Rate:"),t);
    t->setStretchFactor(tmplabel,0);
    logwarnratespinbox = new KIntSpinBox(1,100,1,1,10,t);
    connect(logwarnratespinbox,SIGNAL(valueChanged(int)),this,SLOT(slotLogWarnRateSpinBox(int)));
    tmplabel = new QLabel(i18n(" per "),t);
    t->setStretchFactor(tmplabel,0);
    logwarnrateunitcombobox = new KComboBox((QWidget *)t);
    t->setStretchFactor(logwarnrateunitcombobox,0);
    connect(logwarnrateunitcombobox,SIGNAL(activated(int)),this,SLOT(slotLogWarnRateUnitComboBox(int)));
    logwarnrateunitcombobox->insertItem(i18n("Second"));
    logwarnrateunitcombobox->insertItem(i18n("Minute"));
    logwarnrateunitcombobox->insertItem(i18n("Hour"));
    logwarnrateunitcombobox->insertItem(i18n("Day"));
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t);
    t->setStretchFactor(tmpwidget,1);

    qgrid = new QGrid(2,QGrid::Horizontal,(QWidget *)loggingpage);
    qgrid->setSpacing(spacingHint());

        // Log IP Options
    logipoptionscheckbox = new QCheckBox(i18n("Log IP Options"),(QWidget *)qgrid);
    connect(logipoptionscheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogIPOptions(bool)));
        // Log TCP sequence
    logtcpsequencecheckbox = new QCheckBox(i18n("Log TCP sequence numbers"),(QWidget *)qgrid);
    connect(logtcpsequencecheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogTCPSequence(bool)));
        // Log TCP Options
    logtcpoptionscheckbox = new QCheckBox(i18n("Log TCP Options"),(QWidget *)qgrid);
    connect(logtcpoptionscheckbox,SIGNAL(toggled(bool)),this,SLOT(slotLogTCPOptions(bool)));

        // Logging priority
    t = new QHBox(qgrid);
    t->setSpacing(spacingHint());
    tmplabel = new QLabel(i18n("Logging Priority:"),t);
    t->setStretchFactor(tmplabel,0);
    loglevelcombobox = new KComboBox((QWidget *)t);
    t->setStretchFactor(loglevelcombobox,0);
    connect(loglevelcombobox,SIGNAL(activated(int)),this,SLOT(slotLogLevelComboBox(int)));
    loglevelcombobox->insertItem(i18n("Emergency"));
    loglevelcombobox->insertItem(i18n("Alert"));
    loglevelcombobox->insertItem(i18n("Critical"));
    loglevelcombobox->insertItem(i18n("Error"));
    loglevelcombobox->insertItem(i18n("Warning"));
    loglevelcombobox->insertItem(i18n("Notice"));
    loglevelcombobox->insertItem(i18n("Information"));
    loglevelcombobox->insertItem(i18n("Debug"));
        // Fakey stretch widget.
    tmpwidget = new QWidget(t);
    t->setStretchFactor(tmpwidget,1);

        // Fakey stretch widget.
    tmpwidget = new QWidget((QWidget *)loggingpage);
    loggingpage->setStretchFactor(tmpwidget,1);

        // Advanced page.
    advancedpage = addVBoxPage(i18n("Advanced"));

    t = new QHBox(advancedpage);
    t->setSpacing(spacingHint());
    advancedpage->setStretchFactor(t,0);
    
    t2 = new QVBox(t);
        // Advanced icon.
    tmplabel = new QLabel(t2);
    tmplabel->setPixmap(UserIcon("advanced"));
    t2->setStretchFactor(tmplabel,0);
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t2);
    t2->setStretchFactor(tmpwidget,1);

    t2 = new QVBox(t);
    t2->setSpacing(spacingHint());

    disablefirewallcheckbox = new QCheckBox(i18n("Disable firewall"),(QWidget *)t2);
    connect(disablefirewallcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotDisableFirewall(bool)));

    showadvancedhelpcheckbox = new QCheckBox(i18n("Show advanced protocol help"),(QWidget *)t2);
    connect(showadvancedhelpcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotShowAdvancedHelp(bool)));
    
    tmpqgroupbox = new QVGroupBox(i18n("DHCP"),(QWidget *)t);
        // DHCP client
    t3 = new QHBox(tmpqgroupbox);
    t3->setSpacing(spacingHint());
    enabledhcpccheckbox = new QCheckBox(i18n("Enable DHCP on interfaces:"),(QWidget *)t3);
    t3->setStretchFactor(enabledhcpccheckbox,0);
    connect(enabledhcpccheckbox,SIGNAL(toggled(bool)),this,SLOT(slotEnableDHCPc(bool)));
    dhcpcinterfacenamelineedit = new SimeLineEdit(t3);
    dhcpcinterfacenamevalidator = new InterfaceNameValidator(dhcpcinterfacenamelineedit);
    dhcpcinterfacenamelineedit->setValidator(dhcpcinterfacenamevalidator);
    t3->setStretchFactor(dhcpcinterfacenamelineedit,0);
    connect(dhcpcinterfacenamelineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotDHCPcInterfaceNameLineEdit(const QString &)));
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t3);
    t3->setStretchFactor(tmpwidget,1);
    
        // DHCP server    
    t3 = new QHBox(tmpqgroupbox);
    t3->setSpacing(spacingHint());
    enabledhcpdcheckbox = new QCheckBox(i18n("Enable DHCP server on interfaces:"),(QWidget *)t3);
    t3->setStretchFactor(enabledhcpdcheckbox,0);
    connect(enabledhcpdcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotEnableDHCPd(bool)));
    dhcpdinterfacenamelineedit = new SimeLineEdit(t3);
    dhcpdinterfacenamevalidator = new InterfaceNameValidator(dhcpdinterfacenamelineedit);
    dhcpdinterfacenamelineedit->setValidator(dhcpdinterfacenamevalidator);
    t3->setStretchFactor(dhcpdinterfacenamelineedit,0);
    connect(dhcpdinterfacenamelineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotDHCPdInterfaceNameLineEdit(const QString &)));
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t3);
    t3->setStretchFactor(tmpwidget,1);
        
        // Local Dynamic Port Range
    t3 = new QHBox(t2);
    t3->setSpacing(spacingHint());

    tmplabel = new QLabel(i18n("Local Dynamic Port Range: "),t3);
    t3->setStretchFactor(tmplabel,0);
    localportrangelowspinbox = new KIntSpinBox(1024,65534,1,1024,10,t3);
    connect(localportrangelowspinbox,SIGNAL(valueChanged(int)),this,SLOT(slotLocalPortRangeLowSpinBox(int)));
    t3->setStretchFactor(localportrangelowspinbox,0);
    tmplabel = new QLabel(i18n(":"),t3);
    t3->setStretchFactor(tmplabel,0);
    localportrangehighspinbox = new KIntSpinBox(1025,65535,1,1024,10,t3);
    t3->setStretchFactor(localportrangehighspinbox,0);
    connect(localportrangehighspinbox,SIGNAL(valueChanged(int)),this,SLOT(slotLocalPortRangeHighSpinBox(int)));

        // Allow TCP timestamps
    allowtcptimestampscheckbox = new QCheckBox(i18n("Allow TCP timestamps"),(QWidget *)t2);
    connect(allowtcptimestampscheckbox,SIGNAL(toggled(bool)),this,SLOT(slotAllowTCPTimestamps(bool)));
    
        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t3);
    t3->setStretchFactor(tmpwidget,1);

    t->setStretchFactor(t2,1);

    t = new QHBox(advancedpage);
    t->setSpacing(spacingHint());
    advancedpage->setStretchFactor(t,1);

        // User Defined Protocols box.
    tmpqgroupbox = new QVGroupBox(i18n("User Defined Protocols"),(QWidget *)t);

    userdefinedprotocolslistview = new KListView(tmpqgroupbox);
    userdefinedprotocolslistview->setRootIsDecorated(false);
    userdefinedprotocolslistview->setSelectionMode(QListView::Single);
    userdefinedprotocolslistview->setAllColumnsShowFocus(true);
    userdefinedprotocolslistview->setSorting(-1);   // Turn off sorting.
    userdefinedprotocolslistview->addColumn(i18n("Name"));
    userdefinedprotocolslistview->addColumn(i18n("Type"));
    userdefinedprotocolslistview->addColumn(i18n("Port"));
    
    connect(userdefinedprotocolslistview,SIGNAL(currentChanged(QListViewItem *)),
        this,SLOT(slotUserDefinedProtocolListView(QListViewItem *)));

    t2 = new QHBox(tmpqgroupbox);
    t2->setSpacing(spacingHint());

    newuserdefinedprotocolbutton = new QPushButton(i18n("New Protocol"),t2);
    connect(newuserdefinedprotocolbutton,SIGNAL(clicked()),this,SLOT(slotNewUserDefinedProtocolButton()));
    deleteuserdefinedprotocolbutton = new QPushButton(i18n("Delete Protocol"),t2);
    connect(deleteuserdefinedprotocolbutton,SIGNAL(clicked()),this,SLOT(slotDeleteUserDefinedProtocolButton()));

    t3 = new QHBox(tmpqgroupbox);
    t3->setSpacing(spacingHint());
    
    tmplabel = new QLabel(i18n("Name: "),t3);
    t3->setStretchFactor(tmplabel,0);
    userdefinedprotocolnamelineedit = new SimeLineEdit(t3);
    t3->setStretchFactor(userdefinedprotocolnamelineedit,1);
    connect(userdefinedprotocolnamelineedit,SIGNAL(textChanged(const QString &)),this,SLOT(slotUserDefinedProtocolNameLineEdit(const QString &)));

    t3 = new QHBox(tmpqgroupbox);
    t3->setSpacing(spacingHint());

    tmplabel = new QLabel(i18n("Type: "),t3);
    t3->setStretchFactor(tmplabel,0);
    
        // Type: TCP/UDP
    userdefinedprotocoltypecombobox = new KComboBox((QWidget *)t3);
    userdefinedprotocoltypecombobox->insertItem(i18n("TCP"));
    userdefinedprotocoltypecombobox->insertItem(i18n("UDP"));
    t3->setStretchFactor(userdefinedprotocoltypecombobox,0);
    connect(userdefinedprotocoltypecombobox,SIGNAL(activated(int)),this,SLOT(slotUserDefinedProtocolTypeComboBox(int)));

        // Port
    tmplabel = new QLabel(i18n("Ports: "),t3);
    t3->setStretchFactor(tmplabel,0);
    userdefinedprotocolportstartspinbox = new KIntSpinBox(0,65535,1,1,10,t3);
    connect(userdefinedprotocolportstartspinbox,SIGNAL(valueChanged(int)),this,SLOT(slotUserDefinedProtocolPortStartSpinBox(int)));

    tmplabel = new QLabel(i18n("-"),t3);
    t3->setStretchFactor(tmplabel,0);
    
    userdefinedprotocolportendspinbox = new KIntSpinBox(0,65535,1,1,10,t3);
    connect(userdefinedprotocolportendspinbox,SIGNAL(valueChanged(int)),this,SLOT(slotUserDefinedProtocolPortEndSpinBox(int)));

    userdefinedprotocolbidirectionalcheckbox = new QCheckBox(i18n("Bidirectional"),(QWidget *)t3);
    t3->setStretchFactor(userdefinedprotocolbidirectionalcheckbox,0);
    connect(userdefinedprotocolbidirectionalcheckbox,SIGNAL(toggled(bool)),this,SLOT(slotUserDefinedProtocolBidirectional(bool)));

        // Fakey strecher
    tmpwidget = new QWidget((QWidget *)t3);
    t3->setStretchFactor(tmpwidget,1);

    t2 = new QVBox((QWidget *)t);
    t2->setSpacing(spacingHint());
        
        // Import/Export.
    tmpqgroupbox = new QVGroupBox(i18n("Import/Export"),(QWidget *)t2);
    t2->setStretchFactor(tmpqgroupbox,1);

    tmplabel = new QLabel(i18n("Description:"),tmpqgroupbox);
    descriptionedit = new KEdit(tmpqgroupbox);
    connect(descriptionedit,SIGNAL(textChanged()),this,SLOT(slotDescriptionChanged()));

    t3 = new QHBox(tmpqgroupbox);
    t3->setSpacing(spacingHint());
    importbutton = new QPushButton(i18n("Import..."),t3);
    connect(importbutton,SIGNAL(clicked()),this,SLOT(slotImportButton()));
    exportbutton = new QPushButton(i18n("Export..."),t3);
    connect(exportbutton,SIGNAL(clicked()),this,SLOT(slotExportButton()));

    factorydefaultsbutton = new QPushButton(i18n("Restore to factory defaults..."),t2);
    connect(factorydefaultsbutton,SIGNAL(clicked()),this,SLOT(slotFactoryDefaultsButton()));
    t2->setStretchFactor(factorydefaultsbutton,0);
        	
        // DB Query page
    querypage = addVBoxPage(i18n("Port Reference"));
    queryPageIndex = pageIndex(querypage);

    t = new QVBox(querypage);
    t->setSpacing(spacingHint());
    querypage->setStretchFactor(t,0);

    t2 = new QHBox(t);
    t2->setSpacing(spacingHint());
        // Query icon.
    tmplabel = new QLabel(t2);
    tmplabel->setPixmap(UserIcon("reference"));
    t2->setStretchFactor(tmplabel,0);
        // label
    tmplabel = new QLabel(i18n("Port: "),t2);
    t2->setStretchFactor(tmplabel,0);
        // query string entry
    portquerylineedit = new QLineEdit(t2);
    connect(portquerylineedit,SIGNAL(returnPressed()),this,SLOT(slotPortQueryLineEditReturn()));
    portquerylineedit->setValidator(new QIntValidator(0,65535,portquerylineedit));

        // query button
    portquerybutton = new QPushButton(i18n("Query"),t2);
    connect(portquerybutton,SIGNAL(clicked()),this,SLOT(slotPortQueryButton()));

    tmpwidget = new QWidget((QWidget *)t2);
    t2->setStretchFactor(tmpwidget,5);

    t2 = new QVBox(t);
    t2->setSpacing(spacingHint());

    querybrowser = new KTextBrowser(t2);
    t2->setStretchFactor(querybrowser,3);
    currentquerytext = i18n("<qt><p><b>Enter a port number to query.</b></p></qt>");
    querybrowser->setText(currentquerytext);

    lastPageIndex = -1;
    connect(this,SIGNAL(aboutToShowPage(QWidget *)),this,SLOT(slotAboutToShowPage(QWidget *)));

	readOptions();
    openDefault();
    return true;
}

///////////////////////////////////////////////////////////////////////////
GuarddogApp::~GuarddogApp() {
    delete doc;
    delete pdb;
    delete aboutus;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotZoneListBox(QListBoxItem *item) {
    DEBUG_EVENTS("GuarddogApp::slotZoneListBox()");
    GuarddogDoc::Zone *z;
    
    if(item==0) {
        return;
    }

    if(updatinggui) return;
    updatinggui = true;

    z = doc->zoneAt(zonelistbox->index(item));
    setZoneGUI(*z);
    setZoneAddressGUI(*z);
    setZoneConnectionGUI(*z);
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotNewZoneButton() {
    DEBUG_EVENTS("GuarddogApp::slotNewZoneButton()");
    GuarddogDoc::Zone *newzone;

    if(updatinggui) return;
    updatinggui = true;

    newzone = doc->newZone();
    zonelistbox->insertItem(newzone->name);

    unbuildConnectionGUI();
    buildConnectionGUI();
    deleteProtocolPages();
    createProtocolPages();    
        
        // Select the new zone in the GUI.
    zonelistbox->setSelected(zonelistbox->count()-1,true);
    setZoneGUI(*newzone);
    setZoneAddressGUI(*newzone);
    setZoneConnectionGUI(*newzone);
    
    modified = true;
    updatinggui = false;    
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDeleteZoneButton() {
    DEBUG_EVENTS("GuarddogApp::slotDeleteZoneButton()");
    GuarddogDoc::Zone *deadzone;
    QListIterator<GuarddogDoc::Zone> *zit;
    int i;
    
    if(updatinggui) return;
    updatinggui = true;
    
    i = zonelistbox->currentItem();
    if(i<0) {
        return;
    }
    deadzone = doc->zoneAt(i);
    ASSERT(deadzone!=0);
    
    zonelistbox->removeItem(i); // Remove the zone from the Zone list box.
    unbuildConnectionGUI();
    deleteProtocolPages();
    doc->deleteZone(deadzone);
    createProtocolPages();    
    buildConnectionGUI();

    zit = doc->newZonesIterator();  // Select the first zone in the list box.
    setZoneGUI(*zit->current());
    setZoneAddressGUI(*zit->current());
    setZoneConnectionGUI(*zit->current());

    delete zit;
    zonelistbox->setSelected(0,true);
    
    modified = true;
    updatinggui = false;    
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotZoneNameLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotZoneNameLineEdit()");
    GuarddogDoc::Zone *thiszone;
    int i;    

    if(updatinggui) return;
    updatinggui = true;
    
    i = zonelistbox->currentItem();
    if(i>=0) {
        thiszone = doc->zoneAt(i);
        thiszone->name = s;
        zonelistbox->changeItem(s,i);
        unbuildConnectionGUI();
        buildConnectionGUI();
        deleteProtocolPages();
        createProtocolPages();
        setZoneConnectionGUI(*thiszone);
    }
    
    modified = true;
    updatinggui = false;    
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotZoneCommentLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotZoneCommentLineEdit()");
    GuarddogDoc::Zone *thiszone;

    if(updatinggui) return;
    updatinggui = true;
    
    if(zonelistbox->currentItem()>=0) {
        thiszone = doc->zoneAt(zonelistbox->currentItem());
        thiszone->comment = s;
    }
    modified = true;
    updatinggui = false;    
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotZoneConnectionClicked(QListViewItem *item) {
    DEBUG_EVENTS("GuarddogApp::slotZoneConnectionClicked()");
    GuarddogDoc::Zone *zone,*currentzone;
    bool needupdate;
    needupdate = false;

    if(item==0) return;

    if(updatinggui) return;
    updatinggui = true;

    zone = connectiondict.find(item);
    ASSERT(zone!=0);
    if(zonelistbox->currentItem()>=0) {
        currentzone = doc->zoneAt(zonelistbox->currentItem());
        if(((QCheckListItem *)item)->isOn()) {
            if(currentzone->isConnected(zone)==false) {
                currentzone->connect(zone);
                zone->connect(currentzone);
                needupdate = true;
            }
        } else {
            if(currentzone->isConnected(zone)) {
                currentzone->disconnect(zone);
                zone->disconnect(currentzone);
                needupdate = true;
            }
        }
        if(needupdate) {
            deleteProtocolPages();
            createProtocolPages();
        }
    }
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotServedZoneListBox(QListBoxItem *item) {
    DEBUG_EVENTS("GuarddogApp::slotServedZoneListBox()");
    if(updatinggui) return;
    updatinggui = true;
    
    if(item==0) {
        return;
    }
    
    protocolwidgetstack->raiseWidget(servingzonelistbox->currentItem());
    servinglabel->setText(i18n("Protocols served from zone '%1' to clients in zones:")
        .arg((doc->zoneAt(servingzonelistbox->currentItem()))->name));

    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotProtocolListViewClicked(QListViewItem *item, const QPoint &, int col) {
    DEBUG_EVENTS("GuarddogApp::slotProtocolListViewClicked()");
    QPtrDict <ProtocolDB::ProtocolEntry> *protoitemdict;
    ProtocolDB::ProtocolEntry *protoitem;
    CheckTableListItem *checkitem;
    GuarddogDoc::Zone *thiszone, *outsidezone;
    QListIterator<GuarddogDoc::Zone> *zit;
    int i;

    if(updatinggui) return;
    updatinggui = true;

        // Look up the specific protocol that was clicked.
    protoitemdict = protocolcheckitemdicts.find(item->listView());
    if(protoitemdict==0) {
        updatinggui = false;
        return;
    }

    protoitem = protoitemdict->find(item);

    if(col==0) {
        if(protoitem!=0) {
            displayProtocolHelp(protoitem);
        }
        updatinggui = false;
        return;
    }

    if(protoitem!=0) {
        checkitem = (CheckTableListItem *)item;
            // Find the zone the listview represents.
        thiszone = revprotocolpagedict.find(item->listView());
        ASSERT(thiszone!=0);

            // Which zone does the clicked column belong to?
        outsidezone = 0;
        zit = doc->newZonesIterator();
        for(i=1; zit->current(); ++(*zit)) {
            if(zit->current()!=thiszone && thiszone->isConnected(zit->current())) {
                if(i==col) {
                    outsidezone = zit->current();
                }
                i++;
            }
        }
        ASSERT(outsidezone!=0);

        switch(thiszone->getProtocolState(outsidezone,protoitem)) {
            case GuarddogDoc::Zone::PERMIT:
                thiszone->setProtocolState(outsidezone,protoitem,GuarddogDoc::Zone::REJECT);
                checkitem->setState(col, CheckTableListItem::CROSSED);
                break;
                
            case GuarddogDoc::Zone::REJECT:
                thiszone->setProtocolState(outsidezone,protoitem,GuarddogDoc::Zone::DENY);
                checkitem->setState(col, CheckTableListItem::CLEAR);
                break;
                
            default:    // DENY
                thiszone->setProtocolState(outsidezone,protoitem,GuarddogDoc::Zone::PERMIT);
                checkitem->setState(col, CheckTableListItem::CHECKED);
                break;
        }
        modified = true;

    }
    updatinggui = false;
}


///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotAddressListBox(QListBoxItem *item) {
    DEBUG_EVENTS("GuarddogApp::slotAddressListBox()");
    GuarddogDoc::Zone *thiszone;

    if(item==0) {
        return;
    }
    
    if(updatinggui) return;
    updatinggui = true;

    thiszone = doc->zoneAt(zonelistbox->currentItem());
    zoneaddresslineedit->setText((thiszone->membermachine.at(zoneaddresslistbox->index(item)))->getAddress());
    
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotNewAddressButton() {
    DEBUG_EVENTS("GuarddogApp::slotNewAddressButton()");
    GuarddogDoc::Zone *thiszone;

    if(updatinggui) return;
    updatinggui = true;
    
    if(zonelistbox->currentItem()>=0) {
        thiszone = doc->zoneAt(zonelistbox->currentItem());
        if(thiszone->editable()) {
            thiszone->membermachine.append(new IPRange(i18n("new.address")));
            zoneaddresslistbox->insertItem((thiszone->membermachine.getLast())->getAddress());
            zoneaddresslineedit->setText((thiszone->membermachine.getLast())->getAddress());
            zoneaddresslistbox->setSelected(zoneaddresslistbox->count()-1,true);
        
            zoneaddresslistbox->setDisabled(false);
            deletezoneaddressbutton->setDisabled(false);
            zoneaddresslineedit->setDisabled(false);
        }
    }
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDeleteAddressButton() {
    DEBUG_EVENTS("GuarddogApp::slotDeleteAddressButton()");
    GuarddogDoc::Zone *thiszone;
    int i;

    if(updatinggui) return;
    updatinggui = true;
    
    thiszone = doc->zoneAt(zonelistbox->currentItem());
    ASSERT(thiszone!=0);
    if(thiszone->editable()) {
        i = zoneaddresslistbox->currentItem();
        if(i>=0) {
            zoneaddresslistbox->removeItem(i);
            thiszone->membermachine.remove(i);
            if(thiszone->membermachine.count()) {
                zoneaddresslineedit->setText((thiszone->membermachine.at(0))->getAddress());
                zoneaddresslistbox->setSelected(0,true);
            } else {
                zoneaddresslineedit->setText("");
                zoneaddresslistbox->setDisabled(true);
                deletezoneaddressbutton->setDisabled(true);
                zoneaddresslineedit->setDisabled(true);
            }
        }
    }
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotAddressLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotAddressLineEdit()");
    GuarddogDoc::Zone *thiszone;
    int i;

    if(updatinggui) return;
    updatinggui = true;

    thiszone = doc->zoneAt(zonelistbox->currentItem());
    if(thiszone->editable()) {
        i = zoneaddresslistbox->currentItem();
        *(thiszone->membermachine.at(i)) = s;
        zoneaddresslistbox->changeItem(s,i);    
    }    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotAddressLineEditReturn() {
    DEBUG_EVENTS("GuarddogApp::slotAddressLineEditReturn()");
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDisableFirewall(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotDisableFirewall()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setDisabled(on);
    
    setZonePageEnabled(!on);
    setProtocolPagesEnabled(!on);
    setLoggingPageEnabled(!on);
    setAdvancedPageEnabled(!on);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLocalPortRangeLowSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotLocalPortRangeLowSpinBox()");
    uint start,end;

    if(updatinggui) return;
    updatinggui = true;
    doc->getLocalDynamicPortRange(start,end);
    if((uint)value>=end) {
        end = value+1;
        localportrangehighspinbox->setValue(end);
    }
    doc->setLocalDynamicPortRange(value,end);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLocalPortRangeHighSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotLocalPortRangeHighSpinBox()");
    uint start,end;

    if(updatinggui) return;
    updatinggui = true;
    doc->getLocalDynamicPortRange(start,end);
    if((uint)value<=start) {
        start = value-1;
        localportrangelowspinbox->setValue(start);
    }
    doc->setLocalDynamicPortRange(start,value);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogRejectedPackets(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogRejectedPackets()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogReject(on);
    setLoggingPageEnabled(!doc->isDisabled());
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogDroppedPackets(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogDroppedPackets()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogDrop(on);
    setLoggingPageEnabled(!doc->isDisabled());
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogAbortedTCP(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogAbortedTCP()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogAbortedTCP(on);
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogIPOptions(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogIPOptions()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogIPOptions(on);
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogTCPSequence(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogTCPSequence()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogTCPSequence(on);
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogTCPOptions(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogTCPOptions()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogTCPOptions(on);
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogLevelComboBox(int index) {
    DEBUG_EVENTS("GuarddogApp::slotLogLevelComboBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogLevel(index);
    modified = true;
    updatinggui = false;
}
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogUseRateLimit(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogUseRateLimit()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogRateLimit(on);
    setLoggingPageEnabled(!doc->isDisabled());
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogRateSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotLogRateSpinBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogRate(value);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogRateUnitComboBox(int index) {
    DEBUG_EVENTS("GuarddogApp::slotLogRateUnitComboBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogRateUnit((GuarddogDoc::LogRateUnit)index);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogBurstSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotLogBurstSpinBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogRateBurst(value);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogWarnRateLimit(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotLogWarnRateLimit()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogWarnLimit(on);
    setLoggingPageEnabled(!doc->isDisabled());
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogWarnRateSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotLogWarnRateSpinBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogWarnLimitRate(value);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotLogWarnRateUnitComboBox(int index) {
    DEBUG_EVENTS("GuarddogApp::slotLogWarnRateUnitComboBox()");
    if(updatinggui) return;
    updatinggui = true;
    doc->setLogWarnLimitRateUnit((GuarddogDoc::LogRateUnit)index);
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotShowAdvancedHelp(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotShowAdvancedHelp()");
    if(updatinggui) return;
    updatinggui = true;
    showadvancedhelp =  on;
    if(showadvancedhelp) {
        protocolhelpbrowser->setText(currentadvancedhelptext);
    } else {
        protocolhelpbrowser->setText(currenthelptext);
    }
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotEnableDHCPc(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotEnableDHCPc()");
    if(updatinggui) return;
    updatinggui = true;

    doc->setDHCPcEnabled(on);
    dhcpcinterfacenamelineedit->setEnabled(on);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDHCPcInterfaceNameLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotDHCPcInterfaceNameLineEdit()");
    if(updatinggui) return;
    updatinggui = true;

    doc->setDHCPcInterfaceName(s);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotEnableDHCPd(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotEnableDHCPd()");
    if(updatinggui) return;
    updatinggui = true;

    doc->setDHCPdEnabled(on);
    dhcpdinterfacenamelineedit->setEnabled(on);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDHCPdInterfaceNameLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotDHCPdInterfaceNameLineEdit()");
    if(updatinggui) return;
    updatinggui = true;

    doc->setDHCPdInterfaceName(s);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotAllowTCPTimestamps(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotAllowTCPTimestamps()");
    if(updatinggui) return;
    updatinggui = true;
    
    doc->setAllowTCPTimestamps(on);
    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotNewUserDefinedProtocolButton() {
    DEBUG_EVENTS("GuarddogApp::slotNewUserDefinedProtocolButton()");
    UserDefinedProtocol *newudp;
    
    if(updatinggui) return;
    updatinggui = true;
    
    newudp = doc->newUserDefinedProtocol();
    addUserDefinedProtocolToListBox(newudp);

    deleteProtocolPages();
    createProtocolPages();    
    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::addUserDefinedProtocolToListBox(UserDefinedProtocol *newudp) {
    QString s;
    QListViewItem *t,*ptr;

    ASSERT(newudp!=0);

    s = newudp->getRangeString();
    if(userdefinedprotocolslistview->childCount()==0) {
        t = new QListViewItem(userdefinedprotocolslistview,
            newudp->getName(),
            newudp->getType()==IPPROTO_TCP ? i18n("TCP") : i18n("UDP"),
            s);
    } else {
            // Insert at the end of the list.    
        ptr = userdefinedprotocolslistview->firstChild();
        ASSERT(ptr!=0);
        while(ptr->nextSibling()!=0) {
            ptr = ptr->nextSibling();
        }
            // Do an insert after.
        t = new QListViewItem(userdefinedprotocolslistview,ptr,
            newudp->getName(),
            newudp->getType()==IPPROTO_TCP ? i18n("TCP") : i18n("UDP"),
            s);
    }
    userdefinedprotocolslistview->setSelected(t,true);
    userdefinedprotocolnamelineedit->setEnabled(true);
    deleteuserdefinedprotocolbutton->setEnabled(true);
    userdefinedprotocoltypecombobox->setEnabled(true);
    userdefinedprotocolportstartspinbox->setEnabled(true);
    userdefinedprotocolportendspinbox->setEnabled(true);

    setUserDefinedProtocolGUI(newudp);
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDeleteUserDefinedProtocolButton() {
    DEBUG_EVENTS("GuarddogApp::slotDeleteUserDefinedProtocolButton()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;
    
    if(updatinggui) return;
    updatinggui = true;
    
        // Work out the index of the currently selected User Protocol.
    if(doc->countUserDefinedProtocols()!=0) {
        item = userdefinedprotocolslistview->currentItem();
        i = 0;
        ptr = userdefinedprotocolslistview->firstChild();
        while(item!=0 && ptr!=item) {
            ptr = ptr->nextSibling();
            i++;
        }
        
        thisudp = doc->userDefinedProtocolAt(i);
        ASSERT(thisudp!=0);
        delete item;
        doc->deleteUserDefinedProtocol(thisudp);
        
            // We want i to be the index of the entry that should now
            // be selected.
            // If we deleted the last item in the list then we need
            // to dec i.
        if(i >= (int)doc->countUserDefinedProtocols()) {
            i--;
        }
        if(i<0) {
            setUserDefinedProtocolGUI(0);
            deleteuserdefinedprotocolbutton->setEnabled(false);
        } else {
            setUserDefinedProtocolGUI(doc->userDefinedProtocolAt(i));
            ptr = userdefinedprotocolslistview->firstChild();
            while(i!=0) {
                ptr = ptr->nextSibling();
                i--;
            }
            userdefinedprotocolslistview->setSelected(ptr,true);
        }
        deleteProtocolPages();
        createProtocolPages();    
    }
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolNameLineEdit(const QString &s) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolNameLineEdit()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;

    if(updatinggui) return;
    updatinggui = true;

        // Work out the index of the currently selected User Protocol.
    item = userdefinedprotocolslistview->currentItem();
    i = 0;
    ptr = userdefinedprotocolslistview->firstChild();
    while(item!=0 && ptr!=item) {
        ptr = ptr->nextSibling();
        i++;
    }
    
    thisudp = doc->userDefinedProtocolAt(i);
    ASSERT(thisudp!=0);
    thisudp->setName(s);
    item->setText(0,s);
    
    deleteProtocolPages();
    createProtocolPages();    
    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolPortStartSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolPortStartSpinBox()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;

    if(updatinggui) return;
    updatinggui = true;

        // Work out the index of the currently selected User Protocol.
    item = userdefinedprotocolslistview->currentItem();
    i = 0;
    ptr = userdefinedprotocolslistview->firstChild();
    while(item!=0 && ptr!=item) {
        ptr = ptr->nextSibling();
        i++;
    }
    
    thisudp = doc->userDefinedProtocolAt(i);
    ASSERT(thisudp!=0);
    thisudp->setStartPort(value);
        // Synchronize EndPort
    if((uint)userdefinedprotocolportendspinbox->value() != thisudp->getEndPort()) {
        userdefinedprotocolportendspinbox->setValue((int)thisudp->getEndPort());
    }
    item->setText(2,thisudp->getRangeString());
    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolPortEndSpinBox(int value) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolPortEndSpinBox()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;

    if(updatinggui) return;
    updatinggui = true;

        // Work out the index of the currently selected User Protocol.
    item = userdefinedprotocolslistview->currentItem();
    i = 0;
    ptr = userdefinedprotocolslistview->firstChild();
    while(item!=0 && ptr!=item) {
        ptr = ptr->nextSibling();
        i++;
    }
    
    thisudp = doc->userDefinedProtocolAt(i);
    ASSERT(thisudp!=0);
    thisudp->setEndPort(value);
    if((uint)userdefinedprotocolportstartspinbox->value() != thisudp->getStartPort()) {
        userdefinedprotocolportstartspinbox->setValue((int)thisudp->getStartPort());
    }
    item->setText(2,thisudp->getRangeString());
    
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolTypeComboBox(int index) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolTypeComboBox()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;
   
    if(updatinggui) return;
    updatinggui = true;

        // Work out the index of the currently selected User Protocol.
    item = userdefinedprotocolslistview->currentItem();
    i = 0;
    ptr = userdefinedprotocolslistview->firstChild();
    while(item!=0 && ptr!=item) {
        ptr = ptr->nextSibling();
        i++;
    }
    thisudp = doc->userDefinedProtocolAt(i);
    ASSERT(thisudp!=0);
    if(index==0) {
            //TCP
        thisudp->setType(IPPROTO_TCP);
        item->setText(1,i18n("TCP"));
        userdefinedprotocolbidirectionalcheckbox->setEnabled(false);
    } else {
            // UDP
        thisudp->setType(IPPROTO_UDP);
        item->setText(1,i18n("UDP"));
        userdefinedprotocolbidirectionalcheckbox->setEnabled(true);
    }
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolBidirectional(bool on) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolBidirectional()");
    UserDefinedProtocol *thisudp;
    QListViewItem *item,*ptr;
    int i;
   
    if(updatinggui) return;
    updatinggui = true;

        // Work out the index of the currently selected User Protocol.
    item = userdefinedprotocolslistview->currentItem();
    i = 0;
    ptr = userdefinedprotocolslistview->firstChild();
    while(item!=0 && ptr!=item) {
        ptr = ptr->nextSibling();
        i++;
    }
    thisudp = doc->userDefinedProtocolAt(i);
    ASSERT(thisudp!=0);
    thisudp->setBidirectional(on);

    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotUserDefinedProtocolListView(QListViewItem *item) {
    DEBUG_EVENTS("GuarddogApp::slotUserDefinedProtocolListView()");
    UserDefinedProtocol *thisudp;
    QListViewItem *ptr;
    int i;
    
    if(updatinggui) return;
    updatinggui = true;

    thisudp = 0;
    if(item!=0) {
        i = 0;
        ptr = userdefinedprotocolslistview->firstChild();
        while(item!=0 && ptr!=item) {
            ptr = ptr->nextSibling();
            i++;
        }
        thisudp = doc->userDefinedProtocolAt(i);
    }
    ASSERT(thisudp!=0);
    setUserDefinedProtocolGUI(thisudp);
        
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotImportButton() {
    DEBUG_EVENTS("GuarddogApp::slotImportButton()");
    QString filename;
    QString errorstring;
    GuarddogDoc *tmpdoc;

    updatinggui = true;

    filename = KFileDialog::getOpenFileName(QString::null,QString::null,this,i18n("Import firewall"));
    if(filename.isEmpty()) {
        updatinggui = false;
        return;
    }

    tmpdoc = new GuarddogDoc(pdb);
    if(tmpdoc->openFirewall(filename,errorstring)==false) {
            // Stick up a good ol' error message.
        KMessageBox::error(0,i18n("Guarddog was unable to read the file at %1 as being a Guarddog firewall.\n"
            "This probably means that this file in not actually a Guarddog firewall.\n\n"
            "(Detailed message \"%2\")").arg(filename).arg(errorstring));
        delete tmpdoc;
        updatinggui = false;
        return;
    }
        // That loaded ok. Re-configure the GUI.
    
    
    unbuildGUI();
    delete doc;     //Switcherroo
    doc = tmpdoc;
    buildGUI();
    modified = true;
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotExportButton() {
    DEBUG_EVENTS("GuarddogApp::slotExportButton()");
    QString filename;
    QString errorstring;

    filename = KFileDialog::getSaveFileName(QString::null,QString::null,this,i18n("Export firewall"));
    if(filename.isEmpty()) {
        return;
    }
    if(doc->saveFirewall(filename, errorstring)==false) {
		KMessageBox::error(this,i18n("An error occurred while writing the firewall script to %1.\n\n"
            "(Detailed message: \"%2\")").arg(filename).arg(errorstring));
    }
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotFactoryDefaultsButton() {
    DEBUG_EVENTS("GuarddogApp::slotFactoryDefaultsButton()");
    GuarddogDoc *tmpdoc;

    if(KMessageBox::warningContinueCancel(this,
            i18n("You are sure you want to reset your firewall\n"
            "configuration to the factory default?\n"
            "This will replace your current configuration.\n"
            "Do you wish to continue?"),0,i18n("Continue"))==KMessageBox::Continue) {
    
        tmpdoc = new GuarddogDoc(pdb);
            // That loaded ok. Re-configure the GUI.
        unbuildGUI();
        delete doc;     //Switcherroo
        doc = tmpdoc;
        buildGUI();
        modified = true;
    }
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::slotDescriptionChanged() {
    DEBUG_EVENTS("GuarddogApp::slotDescriptionChanged()");
    doc->description = descriptionedit->text();
    modified = true;
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::addProtocolPage(GuarddogDoc::Zone *thiszone, int id) {
    QListIterator<GuarddogDoc::Zone> *zit;
    KListView *listview;
    QPtrDict <ProtocolDB::ProtocolEntry> *protoitemdict;

    protoitemdict = new QPtrDict <ProtocolDB::ProtocolEntry>();

    ASSERT(protocolwidgetstack!=0);

    listview = new KListView(protocolwidgetstack);
    ASSERT(listview!=0);
    listview->setRootIsDecorated(true);
    listview->setSelectionMode(QListView::NoSelection);
    listview->addColumn(i18n("Network Protocol"));
    connect(listview,SIGNAL(clicked(QListViewItem *,const QPoint &,int)),
        this,SLOT(slotProtocolListViewClicked(QListViewItem *,const QPoint &,int)));
    
    protocolcheckitemdicts.insert((void *)listview,protoitemdict);
    
    zit = doc->newZonesIterator();
    for(; zit->current(); ++(*zit)) {
        if(thiszone->isConnected(zit->current())) {
            listview->addColumn(zit->current()->name);
        }
    }
    
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_CHAT, i18n("Chat"), QString("chat"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_DATA, i18n("Data Serve"), QString("dataserve"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_FILE, i18n("File Transfer"), QString("filetransfer"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_GAME, i18n("Game"), QString("game"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_MAIL, i18n("Mail"), QString("mail"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_MEDIA, i18n("Media"), QString("multimedia"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_NET, i18n("Network"), QString("network"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_SESSION, i18n("Interactive Session"), QString("terminal"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_UNKNOWN, i18n("Miscellaneous"), QString("miscellaneous"), protoitemdict);
    addProtocolClass(thiszone, listview, ProtocolDB::CLASS_CUSTOM, i18n("User Defined"), QString("userdefined"), protoitemdict);
    delete zit;
        
    protocolwidgetstack->addWidget((QWidget *)listview,id);
    protocolpagedict.insert((void *)thiszone,listview);
    revprotocolpagedict.insert((void *)listview,thiszone);
}

///////////////////////////////////////////////////////////////////////////
void GuarddogApp::addProtocolClass(GuarddogDoc::Zone *thiszone, KListView *listview, ProtocolDB::Classification classification,
        QString classname, QString iconname, QPtrDict <ProtocolDB::ProtocolEntry> *protoitemdict) {
    QListIterator<GuarddogDoc::Zone> *zit;
    QListViewItem *appItem;
    QListIterator<ProtocolDB::ProtocolEntry> *proto;
    CheckTableListItem *item;
    int i;
    
    zit = doc->newZonesIterator();
    appItem = new QListViewItem( listview, classname);
	appItem->setPixmap(0, UserIcon(iconname));
    proto = pdb->newDatabaseIterator();
    for(;proto->current(); ++(*proto)) {
        if(proto->current()->classification==classification) {
            item = new CheckTableListItem(appItem);
            protoitemdict->insert((void *)item,proto->current());
            item->setText(0,proto->current()->longname);
            
            for(i=1, zit->toFirst(); zit->current(); ++(*zit)) {
                if(thiszone->isConnected(zit->current())) {
                    switch(thiszone->getProtocolState(zit->current(),proto->current())) {
                        case GuarddogDoc::Zone::PERMIT:
                            item->setState(i, CheckTableListItem::CHECKED);
                            break;
                            
                        case GuarddogDoc::Zone::REJECT:
                            item->setState(i, CheckTableListItem::CROSSED);
                            break;
                            
                        default:    // DENY
                            item->setState(i, CheckTableListItem::CLEAR);
                            break;
                    }
                    i++;
                }
            }
        }
    }
    delete proto;
    delete zit;
}

///////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////
void GuarddogApp::deleteProtocolPages() {
    QListIterator<GuarddogDoc::Zone> *zit;
    KListView *page;

    ASSERT(servingzonelistbox!=0);
        // Clean out the Combo Box.
    servingzonelistbox->clear();
    
        // Dispose of the protocol pages.
    zit = doc->newZonesIterator();
    for(; zit->current(); ++(*zit)) {
        page = protocolpagedict.find(zit->current());
        if(page!=0) {
            protocolwidgetstack->removeWidget(page);
        }
        delete page; // FIXME: delete 'page'?
    }
    delete zit;
    
        // Empty all our dictionaries full of dangling pointers.
    protocolpagedict.clear();
    revprotocolpagedict.clear();
    protocolcheckitemdicts.clear();
}

///////////////////////////////////////////////////////////////////////////

void GuarddogApp::generateProtocolHelp(ProtocolDB::ProtocolEntry *protoitem,
    QString *basicText/*=0*/, QString *advancedText/*=0*/, bool appendMode/*=false*/)
{
    // NOTE: in append mode, strings are not cleared and <qt> tags are not added
    ProtocolDB::ProtocolNetUse *netuseptr;
    QString protoname;
    QString fromname;
    QString toname;
    ProtocolDB::ProtocolNetUseDetail *detailptr;
    bool comma;

    if ( !basicText && !advancedText ) return;
    QString *text = basicText ? basicText : advancedText;

    if (!appendMode) *text = "<qt>";
    text->append("<p><b>");
    text->append(i18n("Name:"));
    text->append("</b>   ");
    text->append(protoitem->longname);
    text->append("</p>");
    if(!(protoitem->description.isNull() || protoitem->description.isEmpty())) {
        text->append("<p><b>");
        text->append(i18n("Description:<br/>"));
        text->append("</b>");
        text->append(protoitem->description);
        text->append("</p>");
    }

    if(protoitem->threat!=ProtocolDB::SCORE_UNKNOWN) {
        text->append("<p><b>");
        text->append(i18n("Security Risk:"));
        text->append("</b>   ");
        switch(protoitem->threat) {
            case ProtocolDB::SCORE_LOW:
                text->append(i18n("Low"));
                break;
            case ProtocolDB::SCORE_MEDIUM:
                text->append(i18n("Medium"));
                break;
            case ProtocolDB::SCORE_HIGH:
                text->append(i18n("High"));
                break;
            default:
                break;
        }
        text->append("</p>");
    }
    if (basicText && advancedText)
    {
        if (appendMode)
            advancedText->append(*basicText);
        else
            *advancedText = *basicText;
    }
    if (basicText && !appendMode) basicText->append("</qt>");

    if (advancedText)
    {
        // Add the advanced text to the other string.
        advancedText->append("<p><b>");
        advancedText->append(i18n("Network Usage:"));
        advancedText->append("</b><ol>");

    for(netuseptr = protoitem->networkuse.first(); netuseptr!=0; netuseptr = protoitem->networkuse.next()) {
            advancedText->append("<li><p><i>");
            advancedText->append(i18n("Description:"));
            advancedText->append("</i> ");
        switch(netuseptr->type) {
            case IPPROTO_TCP:
                protoname = QString("TCP");
                break;
            case IPPROTO_UDP:
                protoname = QString("UDP");
                break;
            case IPPROTO_ICMP:
                protoname = QString("ICMP");
                break;
            default:
                protoname.setNum(netuseptr->type);
                break;
        }
        switch(netuseptr->source) {
            case ProtocolDB::ENTITY_SERVER:
                fromname = i18n("server");
                break;
            case ProtocolDB::ENTITY_CLIENT:
                fromname = i18n("client");
                break;
            default:
                fromname = "";
                break;
        }
        switch(netuseptr->dest) {
            case ProtocolDB::ENTITY_SERVER:
                toname = i18n("server");
                break;
            case ProtocolDB::ENTITY_CLIENT:
                toname = i18n("client");
                break;
            default:
                toname = "";
                break;
        }

        switch(netuseptr->type) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
                    advancedText->append(i18n("%1 %2 connection from %3 to %4.")
                    .arg((netuseptr->type==IPPROTO_UDP) && (netuseptr->bidirectional) ? i18n("Bidirectional ") : (QString)"")
                    .arg(protoname)
                    .arg(fromname)
                    .arg(toname));
                break;
            case IPPROTO_ICMP:
                    advancedText->append(i18n("%1 packet from %2 to %3.")
                    .arg(protoname)
                    .arg(fromname)
                    .arg(toname));
                break;
            
            default:
                    advancedText->append(i18n("%1IP protocol %2 packet from %3 to %4.")
                    .arg(netuseptr->bidirectional ? i18n("Bidirectional ") : (QString)"")
                    .arg(protoname)
                    .arg(fromname)
                    .arg(toname));
                break;
        }
            advancedText->append("</p>");

            // Name/Description
        if(netuseptr->description.isEmpty()==false) {
                advancedText->append("<p><i>");
                advancedText->append(i18n("Name:"));
                advancedText->append("</i>");
                advancedText->append(i18n(" %1").arg(netuseptr->description));
                advancedText->append("</p>");
        }

        switch(netuseptr->type) {
            case IPPROTO_UDP:
            case IPPROTO_TCP:
                    // Source port
                    advancedText->append("<p><i>");
                    advancedText->append(i18n("Source Port:"));
                    advancedText->append("</i> ");
                comma = false;
                for(detailptr = netuseptr->sourcedetaillist.first(); detailptr!=0;
                            detailptr = netuseptr->sourcedetaillist.next()) {
                    if(comma) {
                            advancedText->append(i18n(", "));
                    }
                    switch(detailptr->rangetype) {
                        case ProtocolDB::PORTRANGE_RANGE:
                            if(detailptr->start==detailptr->end) {
                                    advancedText->append(i18n("%1").arg(detailptr->start));
                            } else {
                                    advancedText->append(i18n("%1-%2").arg(detailptr->start).arg(detailptr->end));
                            }
                            break;
                        case ProtocolDB::PORTRANGE_ANY:
                                advancedText->append(i18n("any"));
                            break;
                        case ProtocolDB::PORTRANGE_PRIVILEGED:
                                advancedText->append(i18n("privileged"));
                            break;
                        case ProtocolDB::PORTRANGE_NONPRIVILEGED:
                                advancedText->append(i18n("nonprivileged"));
                            break;
                        case ProtocolDB::PORTRANGE_DYNAMIC:
                                advancedText->append(i18n("dynamic"));
                            break;
                        default:
                            break;
                    }
                    comma = true;
                }
                    advancedText->append("</p>");
                break;
        
            case IPPROTO_ICMP:
                // ICMP
                    advancedText->append("<p><i>");
                    advancedText->append(i18n("Type/Code:"));
                    advancedText->append("</i> ");
                comma = false;
                for(detailptr = netuseptr->sourcedetaillist.first(); detailptr!=0;
                            detailptr = netuseptr->sourcedetaillist.next()) {
                    if(comma) {
                            advancedText->append(i18n(", "));
                    }
                        advancedText->append(i18n("%1/").arg(detailptr->type));
                    if(detailptr->code==-1) {
                            advancedText->append(i18n("*"));
                    } else {
                            advancedText->append(i18n("%1").arg(detailptr->code));
                    }
                    comma = true;
                }
                break;
                
            default:
            
                break;
        }

        if((netuseptr->type==IPPROTO_UDP) || (netuseptr->type==IPPROTO_TCP)) {
                // Dest port
                advancedText->append("<p><i>");
                advancedText->append(i18n("Destination Port:"));
                advancedText->append("</i> ");
            comma = false;
            for(detailptr = netuseptr->destdetaillist.first(); detailptr!=0;
                        detailptr = netuseptr->destdetaillist.next()) {
                if(comma) {
                        advancedText->append(i18n(", "));
                }
                switch(detailptr->rangetype) {
                    case ProtocolDB::PORTRANGE_RANGE:
                        if(detailptr->start==detailptr->end) {
                                advancedText->append(i18n("%1").arg(detailptr->start));
                        } else {
                                advancedText->append(i18n("%1-%2").arg(detailptr->start).arg(detailptr->end));
                        }
                        break;
                    case ProtocolDB::PORTRANGE_ANY:
                            advancedText->append(i18n("any"));
                        break;
                    case ProtocolDB::PORTRANGE_PRIVILEGED:
                            advancedText->append(i18n("privileged"));
                        break;
                    case ProtocolDB::PORTRANGE_NONPRIVILEGED:
                            advancedText->append(i18n("nonprivileged"));
                        break;
                    case ProtocolDB::PORTRANGE_DYNAMIC:
                            advancedText->append(i18n("dynamic"));
                        break;
                    default:
                        break;
                }
                comma = true;
            }
                advancedText->append("</p>");
            }
            advancedText->append("</li>");
        }
        advancedText->append("</ol></p>");
        if (!appendMode) advancedText->append("</qt>");
        }
    }

void GuarddogApp::displayProtocolHelp(ProtocolDB::ProtocolEntry *protoitem)
{
    generateProtocolHelp(protoitem, &currenthelptext, &currentadvancedhelptext);
    if (showadvancedhelp)
    {
        protocolhelpbrowser->setText(currentadvancedhelptext);
    }
    else
    {
        protocolhelpbrowser->setText(currenthelptext);
    }
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

void GuarddogApp::doQuery(const QString &query)
{
    uint count = 0;
    currentquerytext.truncate(0);
    bool ok = false;
    uint port = query.toUInt(&ok);
    if (ok)
    {
        ProtocolDB::ProtocolEntry *pe;
        QList<ProtocolDB::ProtocolEntry> allMatches;
        // search all types
        uchar types[3] = { IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP };
        for(uint i=0; i<1; ++i)
        {
            QList<ProtocolDB::ProtocolEntry> *matches = pdb->lookup(types[i], port);
            if ( matches && ! matches->isEmpty() )
            {
                pe = matches->first();
                while(pe)
                {
                    // acoid duplicates
                    if ( allMatches.contains(pe) == 0 )
                        allMatches.append(pe);
                    pe = matches->next();
                }
            }
        }
        // format all results
        if ( ! allMatches.isEmpty() )
        {
            pe = allMatches.first();
            while(pe)
            {
                ++count;
                if (count == 1)
                    currentquerytext = "<qt>";
                else
                    currentquerytext.append("<hr>");
                generateProtocolHelp(pe, 0, &currentquerytext, true);
                pe = allMatches.next();
            }
        }
    }
    if (count == 0)
    {
        currentquerytext = "<qt><b><i>No matches found for '";
        currentquerytext.append(query);
        currentquerytext.append("'</i></b>");
    }
    currentquerytext.append("</qt>");
    querybrowser->setText(currentquerytext);
}

void GuarddogApp::slotPortQueryLineEditReturn()
{
    DEBUG_EVENTS("GuarddogApp::slotPortQueryLineEditReturn()");
    QString query = portquerylineedit->text();
    doQuery(query);
}

void GuarddogApp::slotPortQueryButton()
{
    DEBUG_EVENTS("GuarddogApp::slotPortQueryButton()");
    QString query = portquerylineedit->text();
    doQuery(query);
}

void GuarddogApp::slotAboutToShowPage(QWidget *page)
{
    int index = pageIndex(page);
    if ( (index == queryPageIndex) && (lastPageIndex != queryPageIndex) )
    {
        enableButtonOK(false);
        enableButtonApply(false);
    }
    else if ( (lastPageIndex == queryPageIndex) && superusermode )
    {
        enableButtonOK(true);
        enableButtonApply(true);
    }
    lastPageIndex = index;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::unbuildGUI() {
    updatinggui = true;
    zonelistbox->clear();
    zoneaddresslistbox->clear();
    unbuildConnectionGUI();
    userdefinedprotocolslistview->clear();
    deleteProtocolPages();
    updatinggui = false;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
void GuarddogApp::unbuildConnectionGUI() {
    connectiondict.clear();
    connectionslistview->clear();
}

///////////////////////////////////////////////////////////////////////////
bool GuarddogApp::resetSystemFirewall() {
    CommandRunner cr(this);

    if(!commandrunnersize.isEmpty()) {
        cr.resize(commandrunnersize);
    }

    cr.setPlainCaption(i18n("Resetting firewall"));
    cr.setHeading(i18n("Resetting firewall...\n\nOutput:"));
QString s =     
    QString(
        "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/sbin\n"
        "FILTERSYS=0\n"
        "if [ -e /sbin/ipchains ]; then\n"
        "FILTERSYS=1\n"
        "fi;\n"
        "if [ -e /usr/sbin/ipchains ]; then\n"
        "FILTERSYS=1\n"
        "fi;\n"
        "if [ -e /usr/local/sbin/ipchains ]; then\n"
        "FILTERSYS=1\n"
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
        "  echo \"%1\"\n"
        "fi;\n"
        "if [ $FILTERSYS -eq 1 ]; then\n"
        "echo \"%2\"\n"
        "echo \"%3\"\n"
        "ipchains -P output ACCEPT\n"
        "ipchains -P input ACCEPT\n"
        "ipchains -P forward ACCEPT\n"
        "ipchains -F forward\n"
        "ipchains -F input\n"
        "ipchains -F output\n"
        "fi\n"
        "if [ $FILTERSYS -eq 2 ]; then\n"
        "echo \"%4\"\n"
        "echo \"%5\"\n"
        "iptables -P OUTPUT ACCEPT\n"
        "iptables -P INPUT ACCEPT\n"
        "iptables -P FORWARD ACCEPT\n"
        "iptables -F FORWARD\n"
        "iptables -F INPUT\n"
        "iptables -F OUTPUT\n"
        "fi;\n"
        "echo \"%6\"\n")
        .arg(i18n("ERROR Can't determine the firewall command! (Is ipchains or iptables installed?)"))
        .arg(i18n("Using ipchains."))
        .arg(i18n("Resetting firewall rules."))
        .arg(i18n("Using iptables."))
        .arg(i18n("Resetting firewall rules."))
        .arg(i18n("Finished."))
        ;
printf("%s",s.ascii());
    cr.run(s);
    
    commandrunnersize = cr.size();
    return true;
}

///////////////////////////////////////////////////////////////////////////
//
// About Button
//
void GuarddogApp::slotUser1() {
    aboutus->show();
}
