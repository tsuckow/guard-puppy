#pragma once

#include <QItemDelegate>
#include <QStandardItemModel>


class rangeEdit:public QWidget
{
QSpinBox* left;
QSpinBox* right;
    public:
    rangeEdit(QWidget* parent): QWidget(parent)
    {
        left = new QSpinBox(this);
        right = new QSpinBox(this);
        QHBoxLayout* layout = new QHBoxLayout();
        layout->setSpacing(0);
        layout->setMargin(0);
        setLayout(layout);
        layout->addWidget(left);
        layout->addWidget(right);
        left->setMinimum(0);
        left->setMaximum(65535);
        right->setMinimum(0);
        right->setMaximum(65535);
    }
    void setValue(int i, int j)
    {
        left->setValue(i);
        right->setValue(j);
    }
    void value(int& i, int& j)
    {
        i = left->value();
        j = right->value();
    }
};

//we need a delegate for the UserDefinedProtocolTreeView, so that we can open up very specific widgets for editing each of the different columns.
//

 class UserDefinedProtocolTreeViewDelegate : public QItemDelegate
{
Q_OBJECT

public:
    UserDefinedProtocolTreeViewDelegate(QObject *parent = 0): QItemDelegate(parent)
    {}
    QWidget * createEditor(QWidget *parent, QStyleOptionViewItem const &, QModelIndex const & index) const
    {
        switch(index.column())
        {
            case 0: //lineEdit
            {
                QLineEdit* editor = new QLineEdit(parent);
                return editor;
            }
            case 1: //comboBox
            {
                QComboBox* editor = new QComboBox(parent);
                editor->addItem("TCP", QVariant(0));
                editor->addItem("UDP", QVariant(1));
                return editor;
            }
            case 2: //rangeEditWidget
            {
                rangeEdit* editor = new rangeEdit(parent);
                return editor;
            }
            case 3: //checkbox
            {
                QCheckBox* editor = new QCheckBox(parent);
                return editor;
            }
            default:
            {
                //do something?
            }
        }
    }

    void setEditorData(QWidget * /*editor*/, QModelIndex const & index) const
    {
         //int value = index.model()->data(index, Qt::EditRole).toInt();
         switch(index.column())
         {
            case 0: //lineEdit
            {
            }
            case 1: //comboBox
            {
            }
            case 2: //rangeEditWidget
            {
            }
            case 3: //checkBox
            {
            }
            default: //what do?
            {
            }
         }
    }

    void setModelData(QWidget * editor, QAbstractItemModel * model, QModelIndex const & index) const
    {//this function needs to store data to the object model AND back to the database.
        switch(index.column())
        {
            case 0: //lineEdit
            {
            }
            case 1: //comboBox
            {
                QComboBox * combo = static_cast<QComboBox*>(editor);
                model->setData(index, combo->currentIndex(), Qt::EditRole);
                model->setData(index, combo->currentText(), Qt::DisplayRole);
                return;
            }
            case 2: //rangeEditWidget
            {
                rangeEdit* range = static_cast<rangeEdit*>(editor);
                int i, j;
                range->value(i,j);
                model->setData(index, i, Qt::EditRole);//get the value from the protocol
                return;
            }
            case 3: //checkBox
            {
            }
            default: //do something?
            {
            }
        }
    }
    void updateEditorGeometry(QWidget * editor, QStyleOptionViewItem const & option, QModelIndex const &) const
    {
        editor->setGeometry(option.rect);
    }
};

