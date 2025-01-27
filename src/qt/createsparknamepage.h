#ifndef _QT_CREATESPARKNAMEPAGE_H
#define _QT_CREATESPARKNAMEPAGE_H

#include <QDialog>

#include "libspark/keys.h"
#include "primitives/transaction.h"

namespace Ui {
    class CreateSparkNamePage;
}

class PlatformStyle;

class CreateSparkNamePage : public QDialog
{
    Q_OBJECT

public:
    explicit CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~CreateSparkNamePage();

private:
    Ui::CreateSparkNamePage *ui;

    CTransactionRef CreateSparkNameTransaction(const std::string &name, const spark::Address &address, const std::string &additionalInfo);
};

#endif // _QT_CREATESPARKNAMEPAGE_H