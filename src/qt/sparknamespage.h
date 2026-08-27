#ifndef BITCOIN_QT_SPARKNAMESPAGE_H
#define BITCOIN_QT_SPARKNAMESPAGE_H

#include <cstdint>

#include <QWidget>

namespace Ui {
    class SparkNamesPage;
}

class PlatformStyle;
class WalletModel;
class AddressTableModel;
class ClientModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QVBoxLayout;
class QScrollArea;
class QFrame;
QT_END_NAMESPACE

/** Page listing the wallet's own registered Spark Names, their expiry, and letting the user create new ones. */
class SparkNamesPage : public QWidget
{
    Q_OBJECT

public:
    explicit SparkNamesPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SparkNamesPage();

    void setModel(WalletModel *model);
    void setClientModel(ClientModel *clientModel);

private:
    Ui::SparkNamesPage *ui;
    const PlatformStyle *platformStyle;
    WalletModel *model;
    AddressTableModel *addressModel;
    ClientModel *clientModel;
    bool refreshScheduled;

    QWidget *emptyState;
    QLabel *emptyIcon_;
    QLabel *emptyTitle_;
    QLabel *emptyDescription_;
    QScrollArea *namesScroll;
    QWidget *namesCardsHost;
    QVBoxLayout *namesCardsLayout;

    void refreshList();
    void scheduleRefreshList();
    void updateCardStatuses(int currentHeight);
    void updateCardStatus(QFrame *card, int currentHeight);
    void updateEmptyState();
    bool eventFilter(QObject *object, QEvent *event) override;
    void applyTheme();
    QFrame *createSparkNameCard(const QString &name, const QString &address, uint64_t validityHeight,
                                 const QString &additionalInfo, int currentHeight);
    void extendSparkName(const QString &name, const QString &address);

private Q_SLOTS:
    void on_createSparkNameButton_clicked();
};

#endif // BITCOIN_QT_SPARKNAMESPAGE_H
