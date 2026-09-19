#ifndef _QT_CREATESPARKNAMEPAGE_H
#define _QT_CREATESPARKNAMEPAGE_H

#include <QDialog>
#include <QPointer>

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
    QString extensionUnavailableReason;
    bool extendMode = false;

public:
    explicit CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~CreateSparkNamePage();

    void setExtendMode(const QString &name, const QString &address);

    void setModel(WalletModel *model);

    void accept() override;

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    Ui::CreateSparkNamePage *ui;
    QPointer<WalletModel> model;
    const PlatformStyle *platformStyle;
    
    bool CreateSparkNameTransaction(const std::string &name, const std::string &address, int numberOfYears, const std::string &additionalInfo);
    void applyTheme();
    void checkSparkBalance();
    void updateFee();
    void chooseExistingAddress();
    void generateSparkAddress();

private Q_SLOTS:
    void on_sparkNameEdit_textChanged(const QString &text);
    void on_numberOfYearsEdit_valueChanged(int value);
};

#endif // _QT_CREATESPARKNAMEPAGE_H
