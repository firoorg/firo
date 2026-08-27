#ifndef MASTERNODELIST_H
#define MASTERNODELIST_H

#include "platformstyle.h"
#include "primitives/transaction.h"
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
    void resizeEvent(QResizeEvent*) override;
private:
    QMenu* contextMenuDIP3;
    int64_t nTimeFilterUpdatedDIP3;
    int64_t nTimeUpdatedDIP3;
    bool fFilterUpdatedDIP3;

    QTimer* timer;
    Ui::MasternodeList* ui;
    ClientModel* clientModel;
    WalletModel* walletModel;

    QString strCurrentFilterDIP3;

    bool mnListChanged;
    QWidget* emptyState;
    QLabel* emptyIcon_{nullptr};
    QLabel* emptyTitle_{nullptr};
    QLabel* emptyDescription_{nullptr};
    QListView* masternodeView;
    QStandardItemModel* masternodeModel;
    QSortFilterProxyModel* masternodeProxy;
    QComboBox* masternodeSort;
    QToolButton* masternodeSortDirection;
    Qt::SortOrder masternodeSortOrder{Qt::AscendingOrder};
    QString selectedProTxHash;

    CDeterministicMNCPtr GetSelectedDIP3MN();

    bool updateDIP3List();
    void updateEmptyState();
    void applyTheme();
    void updateSelection(const QModelIndex& index);
    void sortMasternodes(int index);
    void applyMasternodeSort();
    void toggleMasternodeSortOrder();
    void updateSortDirectionButton();

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
