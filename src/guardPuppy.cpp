
#include <QApplication>
#include <QMessageBox>
#include "unistd.h"

#include "dialog_w.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    GuardPuppyDialog_w guardPuppyDialog( getuid() == 0 );


    if ( getuid()!=0 ) {
        QMessageBox::information(0,QString::null,QString("MORTALMODEWARNING"), QObject::tr(
                "Since you do not have superuser privileges, Guarddog is running with\n"
                "reduced functionality. Firewall scripts may be Imported/Exported, but\n"
                "the system's firewall settings may not be changed.\n"));
    }


    int rc = 0;
    try
    {
        guardPuppyDialog.show();
        rc = app.exec();
    }
    catch ( std::string const & msg )
    {
        std::cout << "Caught: " << msg << std::endl;
    }
    return rc;
}
