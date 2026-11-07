#ifndef FIRO_NOTIFYMNEMONIC_H
#define FIRO_NOTIFYMNEMONIC_H


#include <QWizard>
#include <QStringList>
#include <array>

namespace Ui {
    class NotifyMnemonic;
}

class NotifyMnemonic : public QWizard
{
    Q_OBJECT
public:
    explicit NotifyMnemonic(const QString& mnemonic, QWidget *parent = nullptr);
    ~NotifyMnemonic();

    static void notify();
public Q_SLOTS:
    void reject() override;
protected:
    bool validateCurrentPage() override;
private:
    void applyTheme();
    Ui::NotifyMnemonic *ui;
    const QStringList mnemonicWords;
    std::array<int, 3> wordIndexes;
};

#endif //FIRO_NOTIFYMNEMONIC_H
