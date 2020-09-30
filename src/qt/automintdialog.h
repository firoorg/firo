#ifndef ZCOIN_QT_AUTOMINT_H
#define ZCOIN_QT_AUTOMINT_H

#include "walletmodel.h"

#include <QDialog>
#include <QPainter>
#include <QPaintEvent>

enum class AutoMintMode : uint8_t {
    MintAll, // come from overview page
    AutoMintAll // come from notification
};

namespace Ui {
    class AutoMintDialog;
}

class AutoMintDialog : public QDialog
{
    Q_OBJECT;

public:
    explicit AutoMintDialog(AutoMintMode mode, QWidget *parent = 0);
    ~AutoMintDialog();

public:
    int exec();
    void setModel(WalletModel *model);

    void paintEvent(QPaintEvent *event) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void accept();
    void reject();

private:
    Ui::AutoMintDialog *ui;
    WalletModel *model;
    LelantusModel *lelantusModel;
    bool requiredPassphase;
    bool minting;
    AutoMintMode mode;

    void ensureLelantusModel();
};

#endif // ZCOIN_QT_AUTOMINT_H