#ifndef MASTERNODELIST_H
#define MASTERNODELIST_H

#include "platformstyle.h"
#include "primitives/transaction.h"
#include "util.h"

#include "evo/deterministicmns.h"

#include <QTimer>
#include <QWidget>
#include <QResizeEvent>

#define MASTERNODELIST_UPDATE_SECONDS 3
namespace Ui
{
class MasternodeList;
}

class ClientModel;
class WalletModel;

QT_BEGIN_NAMESPACE
class QModelIndex;
class QComboBox;
class QLabel;
class QListView;
class QSortFilterProxyModel;
class QStandardItemModel;
class QToolButton;
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
    void showOutOfSyncWarning(bool fShow);
    void resizeEvent(QResizeEvent*) override;

    //! What a masternode's status pill reports.
    enum class StatusKind { Enabled, Penalised, Banned };
    struct Status {
        QString text;
        StatusKind kind;
    };
    /**
     * The status pill for a masternode: enabled, enabled with PoSe penalties, or PoSe-banned.
     * @param[in] banned     Whether the node is PoSe-banned.
     * @param[in] poseScore  The node's current PoSe penalty.
     */
    static Status statusFor(bool banned, int poseScore);

private:
    int64_t nTimeUpdatedDIP3;

    QTimer* timer;
    Ui::MasternodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;

    bool mnListChanged;
    QLabel* syncWarning;
    QWidget* emptyState;
    QLabel* emptyIcon_{nullptr};
    QLabel* emptyTitle_{nullptr};
    QLabel* emptyDescription_{nullptr};
    QListView* masternodeView;
    QStandardItemModel* masternodeModel;
    QSortFilterProxyModel* masternodeProxy;
    QComboBox* masternodeSort;
    QToolButton* masternodeSortDirection;

    CDeterministicMNCPtr GetSelectedDIP3MN();
    bool eventFilter(QObject* watched, QEvent* event) override;

    bool updateDIP3List();
    void updateEmptyState();
    void applyTheme();
    void sortMasternodes(int index);
    void applyMasternodeSort();
    void toggleMasternodeSortOrder();
    void updateSortDirectionButton();
    /** Copy the selected node's address held in role, unless it could not be resolved. */
    void copyAddress(int role);

private Q_SLOTS:
    void on_filterLineEditDIP3_textChanged(const QString& strFilterIn);
    void on_checkBoxMyMasternodesOnly_stateChanged(int state);

    void extraInfoDIP3_clicked();
    void copyProTxHash_clicked();
    void copyCollateralOutpoint_clicked();

    void handleMasternodeListChanged();
    void updateDIP3ListScheduled();
};
#endif // MASTERNODELIST_H
