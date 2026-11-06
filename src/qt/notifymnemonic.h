#ifndef FIRO_NOTIFYMNEMONIC_H
#define FIRO_NOTIFYMNEMONIC_H


#include <QWizard>
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
protected:
    bool validateCurrentPage() override;
private Q_SLOTS:
    void cancelEvent();
private:
    void applyTheme();
    Ui::NotifyMnemonic *ui;
    std::array<int, 3> wordIndexes;
};

#endif //FIRO_NOTIFYMNEMONIC_H
