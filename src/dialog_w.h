#pragma once

#include <string>

#include <QDialog>
#include <QFileDialog>
#include <QCheckBox>
#include "ui_guardPuppy.h"

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
    GuardPuppyFireWall & firewall;

public:
    GuardPuppyDialog_w( GuardPuppyFireWall & _firewall )
        : guiReady( false ), firewall( _firewall )
    {
        //! \todo Read program options, i.e window geometery
        setupUi( this );
        if ( firewall.isSuperUserMode() == false )
        {
            //it may be better to have this check in the buttons and
            //tell the user that changes did infact succeed or not.

            //okayPushButton->setEnabled( false );
            //applyPushButton->setEnabled( false );
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
    void protocolStateChanged( std::string const & zoneTo, std::string const & protocol, Zone::ProtocolState state );
    void on_zoneConnectionTableWidget_itemChanged( QTableWidgetItem * item );

    //new
    void on_advImportPushButton_clicked(){
    //! \todo add logic to handle readFirewall failure
        firewall.factoryDefaults();
        std::string filename = QFileDialog::getOpenFileName(this, tr("Export GuardPuppy Config"), "/~", tr("All Files (*)")).toStdString();
        firewall.readFirewall(filename);
    }
    void on_advExportPushButton_clicked(){
        //put a dialog box out that the user can specify a place to save the file
        std::string filename = QFileDialog::getSaveFileName(this, tr("Import GuardPuppy Config"), "/~", tr("All Files (*)")).toStdString();
        firewall.save(filename);
    }
    void on_newUserDefinedProtocolPushButton_clicked(){}
    void on_deleteUserDefinedProtocolPushButton_clicked(){}

    //  All the checkbox options
    void on_logDroppedPacketsCheckBox_stateChanged( int state );
    void on_logRejectPacketsCheckBox_stateChanged( int state );
    void on_logAbortedTcpCheckBox_stateChanged( int state );
    void on_logUserRateLimitCheckBox_stateChanged( int state );
    void on_logWarnRateLimitCheckBox_stateChanged( int state );
    void on_logIpOptionsCheckBox_stateChanged( int state );
    void on_logTcpSequenceCheckBox_stateChanged( int state );
    void on_logTcpOptionsCheckBox_stateChanged( int state );

    void on_disableFirewallCheckBox_stateChanged( int state );
    void on_allowTcpTimeStampsCheckBox_stateChanged( int state );
    void on_enableDhcpCheckBox_stateChanged( int state );
    void on_enableDhcpdCheckBox_stateChanged( int state );

    void on_userDefinedProtocolBidirectionalCheckBox_stateChanged( int state );

    //  The spinboxes
    void on_logRateSpinBox_valueChanged( int value );
    void on_logBurstSpinBox_valueChanged( int value );
    void on_logWarnRateLimitSpinBox_valueChanged( int value );
    void on_localPortRangeLowSpinBox_valueChanged( int value );
    void on_localPortRangeHighSpinBox_valueChanged( int value );
    void on_userDefinedProtocolPortStartSpinBox_valueChanged( int value );
    void on_userDefinedProtocolPortEndSpinBox_valueChanged( int value );

    //logLevelComboBox

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


