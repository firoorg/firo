#include "recover.h"
#include "ui_recover.h"

#include "guiutil.h"

#include "util.h"

#include <boost/filesystem.hpp>

#include <QFileDialog>
#include <QSettings>
#include <QMessageBox>

Recover::Recover(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Recover),
    thread(0)
{
    ui->setupUi(this);
    setCreateNew();
    thread = new QThread(this);

    connect(this, SIGNAL(stopThread()), thread, SLOT(quit()));
    thread->start();
}

Recover::~Recover()
{
    delete ui;
    /* Ensure thread is finished before it is deleted */
    Q_EMIT stopThread();
    thread->wait();
}

void Recover::setCreateNew()
{
    ui->createNew->setChecked(true);
    ui->mnemonicBox->setEnabled(false);
}

void Recover::on_createNew_clicked()
{
    setCreateNew();
}

void Recover::on_recoverExisting_clicked()
{
    ui->mnemonicBox->setEnabled(true);
    ui->use24->setChecked(true);
}

bool Recover::askRecover()
{
    namespace fs = boost::filesystem;
    std::string dataDir = GetDataDir(false).string();
    if(dataDir.empty())
        throw std::runtime_error("Can't get data directory");

    boost::optional<bool> regTest = GetOptBoolArg("-regtest")
    , testNet = GetOptBoolArg("-testnet");

    if (testNet && regTest && *testNet && *regTest)
        throw std::runtime_error("Invalid combination of -regtest and -testnet.");
    if (regTest && *regTest)
        dataDir += "/regtest";
    if (testNet && *testNet)
        dataDir += "/testnet";

    dataDir += "/wallet.dat";

    if(!fs::exists(GUIUtil::qstringToBoostPath(QString::fromStdString(dataDir))))
    {
        Recover recover;
        recover.setWindowIcon(QIcon(":icons/zcoin"));
        while(true)
        {
            if(!recover.exec())
            {
                /* Cancel clicked */
                return false;
            } else {
                if(recover.ui->recoverExisting->isChecked()) {
                    if(recover.ui->use12->isChecked())
                        SoftSetBoolArg("-use12", true);
                    std::string mnemonic = recover.ui->mnemonicWords->text().toStdString();
                    SoftSetArg("-mnemonic", mnemonic);
                }
                break;
            }
        }
    }
    return true;
}