#ifndef ZCOIN_QT_SIGMAPAGE_H
#define ZCOIN_QT_SIGMAPAGE_H

#include <QWidget>

#include "addresstablemodel.h"
#include "sendcoinsentry.h"
#include "platformstyle.h"

namespace Ui {
    class SigmaPage;
}

class SigmaPage : public QWidget
{
    Q_OBJECT

public:
    SigmaPage(const PlatformStyle *platformStyle, QWidget *parent = 0);

private:
    Ui::SigmaPage *ui;
    AddressTableModel *model;

    const PlatformStyle *platformStyle;

private Q_SLOTS:
    void coinSelectionButtonClicked();
};

#endif // ZCOIN_QT_SIGMAPAGE_H
