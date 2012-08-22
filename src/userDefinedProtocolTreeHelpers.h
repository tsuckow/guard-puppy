#pragma once

#include <QObject>
#include <QItemDelegate>
#include <QStandardItemModel>
#include <QSpinBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include "firewall.h"

class rangeEdit:public QWidget
{
QSpinBox* left;
QSpinBox* right;
    public:
    rangeEdit(QWidget* parent);
    void setValue(int i, int j);
    void value(int& i, int& j);

};

//we need a delegate for the UserDefinedProtocolTreeView, so that we can open up very specific widgets for editing each of the different columns.
//

class UDPTreeDelegate : public QItemDelegate
{
    GuardPuppyFireWall * fw;
Q_OBJECT
public:
    UDPTreeDelegate(GuardPuppyFireWall * firewall, QObject *parent = 0);
    ~UDPTreeDelegate();
    QWidget * createEditor(QWidget *parent, QStyleOptionViewItem const &, QModelIndex const & index) const;
    void setEditorData(QWidget * /*editor*/, QModelIndex const & index) const;
    void setModelData(QWidget * editor, QAbstractItemModel * model, QModelIndex const & index) const;
    void updateEditorGeometry(QWidget * editor, QStyleOptionViewItem const & option, QModelIndex const &) const;
private:
    void applyToAllName(QString s, QAbstractItemModel * model, QModelIndex const & index) const;
};

