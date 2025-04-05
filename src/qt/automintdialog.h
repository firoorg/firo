#ifndef FIRO_QT_AUTOMINT_H
#define FIRO_QT_AUTOMINT_H

#include "walletmodel.h"

#include <QDialog>
#include <QPainter>
#include <QPaintEvent>

enum class AutoMintMode : uint8_t {
    MintAll, // come from overview page
    AutoMintAll // come from notification
};

namespace Ui {
    class AutoMintDialog;
}

class CCriticalSectionLocker {
public:
    explicit CCriticalSectionLocker(CCriticalSection& mutex) : m_mutex(mutex) { ENTER_CRITICAL_SECTION(m_mutex); }
    ~CCriticalSectionLocker()   { LEAVE_CRITICAL_SECTION(m_mutex); }
    CCriticalSectionLocker(const CCriticalSectionLocker&) = delete;
    CCriticalSectionLocker& operator=(const CCriticalSectionLocker&) = delete;

private:
    CCriticalSection& m_mutex;
};

class AutoMintDialog : public QDialog
{
    Q_OBJECT;

public:
    explicit AutoMintDialog(AutoMintMode mode, QWidget *parent = 0);
    ~AutoMintDialog();

public:
    int exec() override;
    void setModel(WalletModel *model);

    void paintEvent(QPaintEvent *event) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void accept() override;
    void reject() override;

private:
    enum class AutoMintProgress : uint8_t {
        Start,
        Unlocking,
        Minting
    };

    Ui::AutoMintDialog *ui;
    WalletModel *model;
    LelantusModel *lelantusModel;
    bool requiredPassphase;
    AutoMintProgress progress;
    AutoMintMode mode;

    void ensureLelantusModel();
};

enum class AutoMintSparkMode : uint8_t {
    MintAll, // come from overview page
    AutoMintAll // come from notification
};

class AutoMintSparkDialog : public QDialog
{
    Q_OBJECT;

public:
    explicit AutoMintSparkDialog(AutoMintSparkMode mode, QWidget *parent = 0);
    ~AutoMintSparkDialog();

public:
    int exec() override;
    void setModel(WalletModel *model);

    void paintEvent(QPaintEvent *event) Q_DECL_OVERRIDE;

private Q_SLOTS:
    void accept() override;
    void reject() override;

private:
    enum class AutoMintSparkProgress : uint8_t {
        Start,
        Unlocking,
        Minting
    };

    Ui::AutoMintDialog *ui;
    WalletModel *model;
    SparkModel *sparkModel;
    bool requiredPassphase;
    AutoMintSparkProgress progress;
    AutoMintSparkMode mode;

    void ensureSparkModel();
};

#endif // FIRO_QT_AUTOMINT_H