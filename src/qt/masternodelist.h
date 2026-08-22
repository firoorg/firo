#ifndef MASTERNODELIST_H
#define MASTERNODELIST_H

#include "platformstyle.h"
#include "primitives/transaction.h"
#include "sync.h"
#include "util.h"

#include "evo/deterministicmns.h"

#include <QMenu>
#include <QTimer>
#include <QWidget>
#include <QResizeEvent>

#define MASTERNODELIST_UPDATE_SECONDS 3
#define MASTERNODELIST_FILTER_COOLDOWN_SECONDS 3

namespace Ui
{
class MasternodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
class QEvent;
class QFrame;
class QLabel;
class QScrollArea;
class QVBoxLayout;
QT_END_NAMESPACE

/** Masternode Manager page widget */
class MasternodeList : public QWidget
{
    Q_OBJECT

public:
    explicit MasternodeList(const PlatformStyle* platformStyle, QWidget* parent = 0);
    ~MasternodeList();

    void setClientModel(ClientModel* clientModel);
    void setWalletModel(WalletModel* walletModel);
    void resizeEvent(QResizeEvent*) override;
    void adjustTextSize(int width,int height);
private:
    QMenu* contextMenuDIP3;
    int64_t nTimeFilterUpdatedDIP3;
    int64_t nTimeUpdatedDIP3;
    bool fFilterUpdatedDIP3;

    QTimer* timer;
    Ui::MasternodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;

    // Protects the masternode card list state
    CCriticalSection cs_dip3list;

    QString strCurrentFilterDIP3;

    bool mnListChanged;
    QWidget* emptyState;
    QLabel* emptyIcon_{nullptr};
    QLabel* emptyTitle_{nullptr};
    QLabel* emptyDescription_{nullptr};
    QScrollArea* masternodeScroll;
    QWidget* masternodeCardsHost;
    QVBoxLayout* masternodeCardsLayout;
    QString selectedProTxHash;

    CDeterministicMNCPtr GetSelectedDIP3MN();

    void updateDIP3List();
    void updateEmptyState();
    void applyTheme();
    void restyleMasternodeCards();
    void selectMasternodeCard(QFrame* frame);
    int masternodeCardCount() const;
    QFrame* createMasternodeCard(const QString& address,
                                 const QString& status,
                                 int statusKind,
                                 int poseScore,
                                 int maxPose,
                                 const QString& registered,
                                 const QString& lastPaid,
                                 const QString& nextPayment,
                                 const QString& payout,
                                 const QString& operatorReward,
                                 const QString& collateral,
                                 const QString& collateralId,
                                 const QString& proTxHash);
    bool eventFilter(QObject* watched, QEvent* event) override;

Q_SIGNALS:
    void doubleClicked(const QModelIndex&);

private Q_SLOTS:
    void showContextMenuDIP3(const QPoint&);
    void on_filterLineEditDIP3_textChanged(const QString& strFilterIn);
    void on_checkBoxMyMasternodesOnly_stateChanged(int state);

    void extraInfoDIP3_clicked();
    void copyProTxHash_clicked();
    void copyCollateralOutpoint_clicked();

    void handleMasternodeListChanged();
    void updateDIP3ListScheduled();
};
#endif // MASTERNODELIST_H
