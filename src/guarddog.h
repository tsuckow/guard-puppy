/***************************************************************************
                          guarddog.h  -  description
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

#ifndef GUARDDOG_H
#define GUARDDOG_H

#include <config.h>

// include files for KDE
#include <qpushbutton.h>
#include <qvbox.h>
#include <qhbox.h>
#include <qscrollview.h>
#include <qvalidator.h>
#include <kapp.h>
#include <kdialogbase.h>
#include <kaction.h>
#include <kcombobox.h>
#include <kaboutapplication.h>
#include <klistview.h>
#include <knuminput.h>
#include <klistbox.h>
#include <knumvalidator.h>
#include <qcheckbox.h>
#include <qlineedit.h>
#include <qwidgetstack.h>
#include <ktextbrowser.h>
#include <keditcl.h>

#include "simelineedit.h"
#include "guarddogdoc.h"
#include "protocoldb.h"
#include "checktablelistitem.h"
#include "userdefinedprotocol.h"

#define SYSTEM_RC_FIREWALL	"/etc/rc.firewall" 

class AddressValidator : public QValidator {
    Q_OBJECT
public:
    AddressValidator(QWidget *parent=0,const char *name=0);
    ~AddressValidator();
    
    virtual QValidator::State validate(QString &input, int &pos) const;
    virtual void fixup(QString &input) const;
};

class InterfaceNameValidator : public QValidator {
    Q_OBJECT
public:
    InterfaceNameValidator(QWidget *parent=0,const char *name=0);
    ~InterfaceNameValidator();
    
    virtual QValidator::State validate(QString &input, int &pos) const;
    virtual void fixup(QString &input) const;
};

class GuarddogApp : public KDialogBase {
    Q_OBJECT

public:
    GuarddogApp(const QString &caption);
    ~GuarddogApp();
    bool initialise(bool god);

    void openDefault();
    bool applyFirewall(bool warnfirst);
    bool resetSystemFirewall();

protected:
    void saveOptions();
    void readOptions();

public slots:
    void slotOk();
    void slotApply();
    void slotCancel();
    void slotUser1();
    void slotZoneListBox(QListBoxItem *item);
    void slotServedZoneListBox(QListBoxItem *item);
    void slotProtocolListViewClicked(QListViewItem *item,const QPoint &p,int col);
    void slotNewZoneButton();
    void slotDeleteZoneButton();
    void slotZoneNameLineEdit(const QString &s);
    void slotZoneCommentLineEdit(const QString &s);
    void slotZoneConnectionClicked(QListViewItem *item);
    void slotAddressListBox(QListBoxItem *item);
    void slotNewAddressButton();
    void slotDeleteAddressButton();
    void slotAddressLineEdit(const QString &s);
    void slotAddressLineEditReturn();
    void slotDisableFirewall(bool on);
    void slotLogDroppedPackets(bool on);
    void slotLogRejectedPackets(bool on);
    void slotLogAbortedTCP(bool on);
    void slotLogIPOptions(bool on);
    void slotLogTCPSequence(bool on);
    void slotLogTCPOptions(bool on);
    void slotLogLevelComboBox(int index);
    void slotLogUseRateLimit(bool on);
    void slotLogRateSpinBox(int value);
    void slotLogRateUnitComboBox(int index);
    void slotLogBurstSpinBox(int value);
    void slotLogWarnRateLimit(bool on);
    void slotLogWarnRateSpinBox(int value);
    void slotLogWarnRateUnitComboBox(int index);
    void slotShowAdvancedHelp(bool on);
    void slotEnableDHCPc(bool on);
    void slotDHCPcInterfaceNameLineEdit(const QString &s);
    void slotEnableDHCPd(bool on);
    void slotDHCPdInterfaceNameLineEdit(const QString &s);
    void slotLocalPortRangeLowSpinBox(int value);
    void slotLocalPortRangeHighSpinBox(int value);
    void slotNewUserDefinedProtocolButton();
    void slotDeleteUserDefinedProtocolButton();
    void slotUserDefinedProtocolNameLineEdit(const QString &s);
    void slotUserDefinedProtocolPortStartSpinBox(int value);
    void slotUserDefinedProtocolPortEndSpinBox(int value);
    void slotUserDefinedProtocolTypeComboBox(int index);
    void slotUserDefinedProtocolListView(QListViewItem *item);
    void slotUserDefinedProtocolBidirectional(bool on);
    void slotImportButton();
    void slotExportButton();
    void slotFactoryDefaultsButton();
    void slotDescriptionChanged();
    void slotAllowTCPTimestamps(bool on);
    void slotPortQueryLineEditReturn();
    void slotPortQueryButton();
    void slotAboutToShowPage(QWidget *page);

private:
    GuarddogDoc *doc;   // Holds all the info about the firewall we are building.
    ProtocolDB *pdb;    // The protocol database we are using.

    bool updatinggui;
    bool waspreviousfirewall;       // True if there was a previous Guarddog firewall active/available
                                    // at program startup.
    bool systemfirewallmodified;    // True if the current state of the system has been modified
                                    // since program startup. This is needed at 'Cancel' time when
                                    // we need to decide if we have any 'Apply'ed changes that need
                                    // to be undone.
    bool modified;
    bool showadvancedhelp;
    bool superusermode;

    void buildGUI();
    void unbuildGUI();

        // Pointers to GUI stuff.
        // Zone page
    QHBox *zonepage;
    KListBox *zonelistbox;
    SimeLineEdit *zonenamelineedit;
    QPushButton *zoneconnectionsbutton;
    SimeLineEdit *zonecommentlineedit;
    QPushButton *newzonebutton;
    QPushButton *deletezonebutton;
    void setZoneGUI(GuarddogDoc::Zone &zone);
    KListBox *zoneaddresslistbox;
    QPushButton *newzoneaddressbutton;
    QPushButton *deletezoneaddressbutton;
    SimeLineEdit *zoneaddresslineedit;
    AddressValidator *addressvalidator;
    KListView *connectionslistview;
        // Dictionary of QCheckListItem ptrs mapping to Zone ptrs.
    QPtrDict <GuarddogDoc::Zone> connectiondict;
    void buildConnectionGUI();
    void unbuildConnectionGUI();
    void setZoneAddressGUI(GuarddogDoc::Zone &zone);
    void setZonePageEnabled(bool enabled);
    void setZoneConnectionGUI(GuarddogDoc::Zone &zone);

        // Protocol Page
    QHBox *protocolpage;
    QLabel *servinglabel;
    KListBox *servingzonelistbox;
    QWidgetStack *protocolwidgetstack;
    KTextBrowser *protocolhelpbrowser;
    QString currenthelptext;
    QString currentadvancedhelptext;
    void generateProtocolHelp(ProtocolDB::ProtocolEntry *protoitem,
        QString *basicText=0, QString *advancedText=0, bool appendMode=false);
    void displayProtocolHelp(ProtocolDB::ProtocolEntry *protoitem);

        // Dictionary of Zone pointers mapping to KListView pointers.
    QPtrDict <KListView> protocolpagedict;
    QPtrDict <GuarddogDoc::Zone> revprotocolpagedict;   // and backwards
    
        // Dictionary of KListView pointers mapping to dictionaries of 
        // CheckTableListItem pointers mapping to ProtocolEntry pointers.
    QPtrDict < QPtrDict<ProtocolDB::ProtocolEntry> > protocolcheckitemdicts;
    
    void addProtocolPage(GuarddogDoc::Zone *thiszone, int id);
    void addProtocolClass(GuarddogDoc::Zone *thiszone, KListView *listview, ProtocolDB::Classification classification,
        QString classname, QString iconname, QPtrDict <ProtocolDB::ProtocolEntry> *protoitemdict);
    void createProtocolPages();
    void deleteProtocolPages();
    void setProtocolPagesEnabled(bool enabled);

        // Logging page
    QVBox *loggingpage;
    QCheckBox *logdroppedpacketscheckbox;
    QCheckBox *logabortedtcpcheckbox;
    QCheckBox *logipoptionscheckbox;
    QCheckBox *logtcpsequencecheckbox;
    QCheckBox *logtcpoptionscheckbox;
    KComboBox *loglevelcombobox;
    QCheckBox *loguseratelimitcheckbox;
    KIntSpinBox *logratespinbox;
    KComboBox *lograteunitcombobox;
    KIntSpinBox *logburstspinbox;
    QCheckBox *logwarnratelimitcheckbox;
    KIntSpinBox *logwarnratespinbox;
    KComboBox *logwarnrateunitcombobox;
    void setLoggingPageEnabled(bool enabled);

        // Advanced page
    QVBox *advancedpage;
    QCheckBox *disablefirewallcheckbox;
    QCheckBox *showadvancedhelpcheckbox;
    QCheckBox *logrejectcheckbox;
    KIntSpinBox *localportrangelowspinbox;
    KIntSpinBox *localportrangehighspinbox;
    KListView *userdefinedprotocolslistview;
    SimeLineEdit *userdefinedprotocolnamelineedit;
    QPushButton *newuserdefinedprotocolbutton;
    QPushButton *deleteuserdefinedprotocolbutton;
    KComboBox *userdefinedprotocoltypecombobox;
    KIntSpinBox *userdefinedprotocolportstartspinbox;
    KIntSpinBox *userdefinedprotocolportendspinbox;
    QCheckBox *userdefinedprotocolbidirectionalcheckbox;
    QPushButton *importbutton;
    QPushButton *exportbutton;
    QPushButton *factorydefaultsbutton;
    KEdit *descriptionedit;
    QCheckBox *enabledhcpccheckbox;
    SimeLineEdit *dhcpcinterfacenamelineedit;
    InterfaceNameValidator *dhcpcinterfacenamevalidator;
    QCheckBox *enabledhcpdcheckbox;
    SimeLineEdit *dhcpdinterfacenamelineedit;
    InterfaceNameValidator *dhcpdinterfacenamevalidator;
    QCheckBox *allowtcptimestampscheckbox;
    
        // Query page
    QVBox *querypage;
    int queryPageIndex, lastPageIndex;
    QLineEdit *portquerylineedit;
    QPushButton *portquerybutton;
    KTextBrowser *querybrowser;
    QString currentquerytext;
    void doQuery(const QString &query);

    void setAdvancedPageEnabled(bool enabled);
    void addUserDefinedProtocolToListBox(UserDefinedProtocol *newudp);

    void setUserDefinedProtocolGUI(UserDefinedProtocol *userprotocol);
    KAboutApplication *aboutus;
    QSize commandrunnersize;

    void copyFile(const char *src, const char *dest);
};

#endif // GUARDDOG_H
