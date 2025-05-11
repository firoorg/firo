#ifndef _QT_CREATESPARKNAMEPAGE_H
#define _QT_CREATESPARKNAMEPAGE_H

#include <QDialog>

#include "walletmodel.h"

#include "libspark/keys.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"

namespace Ui {
    class CreateSparkNamePage;
}

class PlatformStyle;

class CreateSparkNamePage : public QDialog
{
    Q_OBJECT

private:
    QString feeText;

public:
    explicit CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~CreateSparkNamePage();

    void setModel(WalletModel *model);

    void accept() override;

private:
    Ui::CreateSparkNamePage *ui;
    WalletModel *model;
    
    bool CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo);

    void updateFee();

private Q_SLOTS:
    void on_generateButton_clicked();
    void on_sparkNameEdit_textChanged(const QString &text);
    void on_numberOfYearsEdit_valueChanged(int value);
};

#endif // _QT_CREATESPARKNAMEPAGE_H