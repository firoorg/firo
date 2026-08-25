#ifndef BITCOIN_QT_SPARKNAMESPAGE_H
#define BITCOIN_QT_SPARKNAMESPAGE_H

#include <QWidget>

namespace Ui {
    class SparkNamesPage;
}

class PlatformStyle;
class WalletModel;

QT_BEGIN_NAMESPACE
class QLabel;
class QVBoxLayout;
class QScrollArea;
class QFrame;
class QShowEvent;
QT_END_NAMESPACE

/** Page listing the wallet's own registered Spark Names, their expiry, and letting the user create new ones. */
class SparkNamesPage : public QWidget
{
    Q_OBJECT

public:
    explicit SparkNamesPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SparkNamesPage();

    void setModel(WalletModel *model);

protected:
    void showEvent(QShowEvent *event) override;

private:
    Ui::SparkNamesPage *ui;
    const PlatformStyle *platformStyle;
    WalletModel *model;

    QWidget *emptyState;
    QLabel *emptyIcon_;
    QLabel *emptyTitle_;
    QLabel *emptyDescription_;
    QScrollArea *namesScroll;
    QWidget *namesCardsHost;
    QVBoxLayout *namesCardsLayout;

    void refreshList();
    void updateEmptyState();
    void applyTheme();
    QFrame *createSparkNameCard(const QString &name, const QString &address, const QString &expiry,
                                 int statusKind, const QString &additionalInfo);
    void extendSparkName(const QString &name, const QString &address);

private Q_SLOTS:
    void on_createSparkNameButton_clicked();
};

#endif // BITCOIN_QT_SPARKNAMESPAGE_H
