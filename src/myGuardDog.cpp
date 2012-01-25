
#include <QApplication>
#include <QMessageBox>
#include "unistd.h"

#include "guarddogDialog_w.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    GuardDogDialog_w guardDogDialog( getuid() == 0 );


    if ( getuid()!=0 ) {
        QMessageBox::information(0,QString::null,QString("MORTALMODEWARNING"), QObject::tr(
                "Since you do not have superuser privileges, Guarddog is running with\n"
                "reduced functionality. Firewall scripts may be Imported/Exported, but\n"
                "the system's firewall settings may not be changed.\n"));
    }



    guardDogDialog.show();
    return app.exec();
}
