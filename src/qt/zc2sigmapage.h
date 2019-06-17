// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ZC2SIGMAPAGE_H
#define BITCOIN_QT_ZC2SIGMAPAGE_H

#include <memory>

#include <QWidget>

class AddressTableModel;
class OptionsModel;
class PlatformStyle;
class Zc2SigmaModel;

namespace Ui {
    class Zc2SigmaPage;
}

QT_BEGIN_NAMESPACE
class QItemSelection;
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
class QTableView;
QT_END_NAMESPACE

class Zc2SigmaPage : public QWidget
{
    Q_OBJECT

public:

    explicit Zc2SigmaPage(const PlatformStyle *platformStyle, QWidget *parent);
    ~Zc2SigmaPage();

    void createModel();

private:
    Ui::Zc2SigmaPage *ui;
    std::shared_ptr<Zc2SigmaModel> model;

private Q_SLOTS:
    void on_remintButton_clicked();
    void selectionChanged();

Q_SIGNALS:
    void sendCoins(QString addr);
};

#endif // BITCOIN_QT_ADDRESSBOOKPAGE_H
