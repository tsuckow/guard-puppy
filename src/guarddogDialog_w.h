#include <QDialog>
#include "ui_guarddog.h"

#include <iostream>
#include <boost/foreach.hpp>

#include "guardDogFirewall.h"

#include "zone.h"

class GuardDogDialog_w : public QDialog, Ui::GuardDogDialog
{
    Q_OBJECT;
    bool guiReady;
    GuardDogFireWall firewall;

public:
    GuardDogDialog_w( bool god )
        : guiReady( false ), firewall( god, this )
    {
        setupUi( this );
        if ( firewall.isSuperUserMode() == false )
        {
            okayPushButton->setEnabled( false );
            applyPushButton->setEnabled( false );
        }
        guiReady = true;
        rebuildGui();
    }

    void rebuildGui();
    void setZoneGUI( ::Zone const & zone);
    void setZoneAddressGUI( ::Zone const & zone);
    void setZonePageEnabled( ::Zone const & thisZone, bool enabled);
    void setZoneConnectionGUI( ::Zone const & zone);
    void setUserDefinedProtocolGUI( UserDefinedProtocol const & userprotocol) ;
    void buildConnectionGUI() ;
    void createProtocolPages();
    void setProtocolPagesEnabled(bool enabled);
    void setAdvancedPageEnabled(bool enabled);
    void setLoggingPageEnabled(bool enabled);



private slots:
    void on_aboutPushButton_clicked();
    void on_okayPushButton_clicked();
    void on_cancelPushButton_clicked();
    void on_applyPushButton_clicked();

};


