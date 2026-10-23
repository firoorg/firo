#ifndef BITCOIN_QT_ASSETSPAGE_H
#define BITCOIN_QT_ASSETSPAGE_H

#include <QWidget>

class ClientModel;
class PlatformStyle;
class WalletModel;

namespace spark {
class CSparkAssetTxData;
}

QT_BEGIN_NAMESPACE
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTableWidget;
class QTextEdit;
class QWidget;
QT_END_NAMESPACE

/** Spark assets page: portfolio, created assets, and registration. */
class AssetsPage : public QWidget
{
    Q_OBJECT

public:
    explicit AssetsPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);

    void setModel(WalletModel *model);
    void setClientModel(ClientModel *clientModel);

private Q_SLOTS:
    void applyCreateFieldState();
    void clearCreateForm();
    void estimateCreateFee();
    void updateAdminField();
    void scheduleRefreshAssets();
    void refreshAssets();
    void updateMintButton();
    void updateBurnButton();
    void updateEditButton();
    void updateTransferButton();
    void updateReceiveAssetButton();
    void refreshActivity();
    void refreshPortfolio();
    void applyPortfolioFilter();
    void applyCreatedFilter(bool refreshSelectionActivity = false);
    void updatePortfolioDetails();
    void updateSendButton();
    void sendSelectedAsset();
    void receiveSelectedAsset();
    void receiveCreatedAsset();
    void mintSelectedAsset();
    void burnSelectedAsset();
    void editSelectedAsset();
    void transferSelectedAsset();
    void submitCreateAsset();

private:
    /** Fill \p addressOut when the selected admin address can sign. */
    bool resolveAdminAddress(std::string& addressOut, QString& errorOut) const;
    /** Check the form and fill \p assetData. Does not unlock the wallet or build a transaction. */
    bool readCreateForm(spark::CSparkAssetTxData& assetData, QString& errorOut) const;

private:
    ClientModel *clientModel;
    WalletModel *model;
    bool assetsRefreshScheduled;

    QCheckBox *fungible;
    QLineEdit *symbol;
    QLineEdit *name;
    QComboBox *precision;
    QLineEdit *supply;
    QComboBox *resupply;
    QTextEdit *description;
    QTextEdit *metadata;
    QCheckBox *useDefaultAdmin;
    QLabel *adminAddress;
    QLineEdit *customAdmin;
    QWidget *customAdminField;
    QLabel *adminError;
    QPushButton *createAssetButton;
    QPushButton *mintButton;
    QPushButton *burnButton;
    QPushButton *editButton;
    QPushButton *transferButton;
    QPushButton *sendButton;
    QPushButton *receiveButton;
    QPushButton *receiveAssetButton;
    QTableWidget *createdAssetsTable;
    QLabel *createdAssetsCount;
    QWidget *createdAssetsEmpty;
    QLabel *createdEmptyTitle;
    QLabel *createdEmptyHint;
    QLineEdit *createdSearch;
    QPushButton *createdFilters[2];
    int createdFilter;
    bool createdSelectionShown;
    QTableWidget *activityTable;
    QLabel *activityEmpty;
    QLabel *activitySubtitle;
    QLineEdit *portfolioSearch;
    QTableWidget *portfolioTable;
    QLabel *portfolioCount;
    QWidget *portfolioEmpty;
    QLabel *portfolioDetails[9];

    bool walletControlsAddress(const std::string& admin) const;
    void showReceiveAddress(const QString& symbol, const QString& name);
};

#endif // BITCOIN_QT_ASSETSPAGE_H
