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
    ~MyOwnSpats() override;

    // Set the client model for this page
    void setClientModel(ClientModel* clientModel);

    // Set the wallet model for this page
    void setWalletModel(WalletModel* walletModel);
    void adjustTextSize(int width, int height);

protected:
    void resizeEvent(QResizeEvent*) override;

private:
    QTimer* timer_;
    const std::unique_ptr< Ui::MyOwnSpats > ui_;
    ClientModel* client_model_{};
    WalletModel* wallet_model_{};
};

#endif // MYOWNSPATS_H_INCLUDED
