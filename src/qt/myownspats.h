#ifndef MYOWNSPATS_H_INCLUDED
#define MYOWNSPATS_H_INCLUDED

#include <QWidget>
#include <QResizeEvent>

#include "platformstyle.h"

namespace Ui
{
class MyOwnSpats;
}

class ClientModel;
class WalletModel;

/** "My Own Spats" Manager page widget */
class MyOwnSpats : public QWidget
{
    Q_OBJECT

public:
    explicit MyOwnSpats(const PlatformStyle* platformStyle, QWidget* parent = 0);
    ~MyOwnSpats();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void resizeEvent(QResizeEvent*) override;
    void adjustTextSize(int width, int height);

private:
    QTimer* timer;
    const std::unique_ptr< Ui::MyOwnSpats > ui;
    ClientModel* clientModel;
    WalletModel* walletModel;
};

#endif // MYOWNSPATS_H_INCLUDED
