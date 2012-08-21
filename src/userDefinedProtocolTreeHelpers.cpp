
#include "userDefinedProtocolTreeHelpers.h"


rangeEdit::rangeEdit(QWidget* parent): QWidget(parent)
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


void rangeEdit::setValue(int i, int j)
{
    left->setValue(i);
    right->setValue(j);
}
void rangeEdit::value(int& i, int& j)
{
    i = left->value();
    j = right->value();
}

UDPTreeDelegate::UDPTreeDelegate(QObject *parent):QItemDelegate(parent)
{
}
UDPTreeDelegate::~UDPTreeDelegate()
{
}

QWidget * UDPTreeDelegate::createEditor(QWidget *parent, QStyleOptionViewItem const &, QModelIndex const & index) const
{
    QString string = index.model()->data(index, Qt::DisplayRole).toString();
    if(string=="")
        return (QWidget*)(void*)0;
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
        case 3: //Combobox
        {
            QComboBox* editor = new QComboBox(parent);
            editor->addItem("Bidirectional", 0);
            editor->addItem("Unidirectional", 1);
            return editor;
        }
        default:
        {
            return (QWidget*)(void*)0;
        }
    }
}

void UDPTreeDelegate::setEditorData(QWidget * editor, QModelIndex const & index) const
{
     int value = index.model()->data(index, Qt::EditRole).toInt();
     QString string = index.model()->data(index, Qt::DisplayRole).toString();
     if(!editor)
         return;
     switch(index.column())
     {
        case 0: //lineEdit
        {
            QLineEdit * edit = static_cast<QLineEdit *>(editor);
            edit->setText(string);
            return;
        }
        case 1: //comboBox
        {
            QComboBox * edit = static_cast<QComboBox *>(editor);
            edit->setCurrentIndex(value);
            return;
        }
        case 2: //rangeEditWidget
        {
            rangeEdit * edit = static_cast<rangeEdit *>(editor);
            edit->setValue(value, value);
            return;
        }
        case 3: //comboBox
        {
            QComboBox * edit = static_cast<QComboBox *>(editor);
            edit->setCurrentIndex(value);
            return;
        }
        default: //what do?
        {
        }
     }
     return;
}


void UDPTreeDelegate::setModelData(QWidget * editor, QAbstractItemModel * model, QModelIndex const & index) const
{//this function needs to store data to the object model AND back to the database.
    if(!editor)
        return;
    switch(index.column())
    {
        case 0: //lineEdit
        {
            QLineEdit * line = static_cast<QLineEdit*>(editor);
            model->setData(index, line->text(), Qt::DisplayRole);
            model->setData(index, line->text(), Qt::EditRole);
            return;
        }
        case 1: //comboBox
        {
            QComboBox * combo = static_cast<QComboBox*>(editor);
            model->setData(index, combo->currentIndex(), Qt::EditRole);
            model->setData(index, combo->currentText(), Qt::DisplayRole);
            //set the firewall data here as well
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
        case 3:
        {
            QComboBox * combo = static_cast<QComboBox*>(editor);
            model->setData(index, combo->currentIndex(), Qt::EditRole);
            model->setData(index, combo->currentText(), Qt::DisplayRole);
            return;
        }
        default: //do something?
        {
        }
    }
    return;
}
void UDPTreeDelegate::updateEditorGeometry(QWidget * editor, QStyleOptionViewItem const & option, QModelIndex const &) const
{
    if(!editor)
        return;
    editor->setGeometry(option.rect);
}

