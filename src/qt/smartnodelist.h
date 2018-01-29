#ifndef SMARTNODELIST_H
#define SMARTNODELIST_H

#include "primitives/transaction.h"
#include "platformstyle.h"
#include "sync.h"
#include "util.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>

#define MY_SMARTNODELIST_UPDATE_SECONDS                 60
#define SMARTNODELIST_UPDATE_SECONDS                    15
#define SMARTNODELIST_FILTER_COOLDOWN_SECONDS            3

namespace Ui {
    class SmartnodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Smartnode Manager page widget */
class SmartnodeList : public QWidget
{
    Q_OBJECT

public:
    explicit SmartnodeList(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SmartnodeList();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void StartAlias(std::string strAlias);
    void StartAll(std::string strCommand = "start-all");

private:
    QMenu *contextMenu;
    int64_t nTimeFilterUpdated;
    bool fFilterUpdated;

public Q_SLOTS:
    void updateMySmartnodeInfo(QString strAlias, QString strAddr, const COutPoint& outpoint);
    void updateMyNodeList(bool fForce = false);
    void updateNodeList();

Q_SIGNALS:

private:
    QTimer *timer;
    Ui::SmartnodeList *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;

    // Protects tableWidgetSmartnodes
    CCriticalSection cs_mnlist;

    // Protects tableWidgetMySmartnodes
    CCriticalSection cs_mymnlist;

    QString strCurrentFilter;

private Q_SLOTS:
    void showContextMenu(const QPoint &);
    void on_filterLineEdit_textChanged(const QString &strFilterIn);
    void on_startButton_clicked();
    void on_startAllButton_clicked();
    void on_startMissingButton_clicked();
    void on_tableWidgetMySmartnodes_itemSelectionChanged();
    void on_UpdateButton_clicked();
};
#endif // SMARTNODELIST_H
