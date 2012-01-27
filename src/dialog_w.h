#pragma once

#include <QDialog>
#include <QCheckBox>
#include "ui_guardPuppy.h"

#include <iostream>
#include <boost/foreach.hpp>

#include "firewall.h"

#include "zone.h"

class ProtocolCheckBox : public QCheckBox
{
    Q_OBJECT;

    std::string zoneTo;
    std::string protocol;
public:
    ProtocolCheckBox( std::string const & _zoneTo, std::string const & _protocol, QWidget * parent )
     : QCheckBox( parent ), zoneTo( _zoneTo ), protocol( _protocol )
    {
    }
signals:
    void protocolStateChanged( std::string const & , std::string const & , Zone::ProtocolState );
public slots:
    void stateChanged(int);
};


class GuardPuppyDialog_w : public QDialog, Ui::GuardPuppyDialog
{
    Q_OBJECT;
    bool guiReady;
    GuardPuppyFireWall firewall;

public:
    GuardPuppyDialog_w( bool god )
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

    void on_protocolZoneListWidget_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneListWidget_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneNameLineEdit_textChanged( QString const & text );
    void on_zoneAddressListBox_currentItemChanged( QListWidgetItem * current, QListWidgetItem * previous );
    void on_zoneAddressLineEdit_textChanged( QString const & text );
    void on_newZoneAddressPushButton_clicked();
    void on_deleteZoneAddressPushButton_clicked();
    void on_newZonePushButton_clicked();
    void on_deleteZonePushButton_clicked();
    void on_tabWidget_currentChanged( int index );
    void on_protocolTreeWidget_itemClicked( QTreeWidgetItem * item, int column );
    void on_protocolTreeWidget_itemChanged( QTreeWidgetItem * item, int column );
    void on_protocolStateChanged( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state );
    void on_zoneConnectionTableWidget_itemChanged( QTableWidgetItem * item );

private:
    std::string currentZoneName() const
    {
        if ( zoneListWidget->currentItem() )
            return zoneListWidget->currentItem()->text().toStdString();
        return "";
    }
    std::string currentProtocolZoneName() const
    {
        if ( protocolZoneListWidget->currentItem() )
            return protocolZoneListWidget->currentItem()->text().toStdString();
        return "";
    }
    std::string currentMachineName() const
    {
        if ( zoneAddressListBox->currentItem() )
            return zoneAddressListBox->currentItem()->text().toStdString();
        return "";
    }



};


