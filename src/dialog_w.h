#pragma once

#include <string>

#include <QDialog>
#include <QFileDialog>
#include <QCheckBox>
#include <QErrorMessage>

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

    class AddProtocolToTable_
    {
    GuardPuppyDialog_w & g;
    std::vector<std::string> connectedZones;
    public:
        AddProtocolToTable_(GuardPuppyDialog_w & i, std::vector<std::string> s):g(i), connectedZones(s)
        {}
        void operator()(ProtocolEntry const & pe);
    };
    
    class AddUDPToTable_
    {
    QTableWidget * t;
    public:
        AddUDPToTable_( QTableWidget * t_):t(t_)
        {}
        void operator()(ProtocolEntry const & pe)
        {
            if(pe.Classification == "User Defined")
            {
                t->insertRow( t->rowCount() );
                t->setItem( t->rowCount()-1, 0, new QTableWidgetItem( pe.getName().c_str() ) );
                t->setItem( t->rowCount()-1, 1, new QTableWidgetItem( pe.getType()==IPPROTO_TCP ? QObject::tr("TCP") : QObject::tr("UDP") ) );
                t->setItem( t->rowCount()-1, 2, new QTableWidgetItem( pe.getRangeStringUDP().c_str() ) );
            }
        }
    };

    class numberOfUDP_
    {
        int count;
    public:
        numberOfUDP_():count(0)
        {}
        int value(){return count;}
        void reset() {count = 0;}
        void operator()(ProtocolEntry const & pe)
        {
            if(pe.Classification == "User Defined")
            {
                count++;
                std::cerr << "UDP FOUND:" << count << std::endl;
            }
        }
    };
    class changeProtocolName_
    {
        std::string s;
    public:
        changeProtocolName_(std::string s_):s(s_)
        {}
        void operator()(ProtocolEntry & pe)
        {
            pe.name = s;
            pe.longname = s;
        }
    };


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
    void setUserDefinedProtocolGUI( std::string const &) ;
    void buildConnectionGUI() ;
    void createProtocolPages();
    void setProtocolPagesEnabled(bool enabled);
    void setAdvancedPageEnabled(bool enabled);
    void setLoggingPageEnabled(bool enabled);
    void createUdpTableWidget();


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

    void on_advImportPushButton_clicked();
    void on_advExportPushButton_clicked();
    void on_advRestoreFactoryDefaultsPushButton_clicked();

    void on_newUserDefinedProtocolPushButton_clicked();
    void on_deleteUserDefinedProtocolPushButton_clicked();

    void on_userDefinedProtocolTableWidget_itemSelectionChanged();
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

    void on_userDefinedProtocolBidirectionalCheckBox_stateChanged( int state );//

    //  The spinboxes
    void on_logRateSpinBox_valueChanged( int value );
    void on_logBurstSpinBox_valueChanged( int value );
    void on_logWarnRateLimitSpinBox_valueChanged( int value );
    void on_localPortRangeLowSpinBox_valueChanged( int value );
    void on_localPortRangeHighSpinBox_valueChanged( int value );

//    void on_userDefinedProtocolTypeComboBox_currentIndexChanged(int value);     //
    void on_userDefinedProtocolNameLineEdit_returnPressed();  //
    void on_userDefinedProtocolPortStartSpinBox_valueChanged( int value );      //
    void on_userDefinedProtocolPortEndSpinBox_valueChanged( int value );        //


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


