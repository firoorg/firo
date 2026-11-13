#ifndef FIRO_RECOVER_H
#define FIRO_RECOVER_H

#include <QDialog>
#include <QList>

class QLabel;
class QLineEdit;

namespace Ui {
    class Recover;
}

class Recover : public QDialog
{
    Q_OBJECT

public:
    explicit Recover(QWidget *parent = 0);
    ~Recover();

    /**
     * @param[out] multisig  set to whether the user asked for the new wallet to become a multisig wallet
     */
    static bool askRecover(bool& newWallet, bool* multisig = nullptr);

private Q_SLOTS:
    void submit();

private:
    void applyTheme();
    void showPage(QWidget* page);
    void setWordCount(int count);
    void wordEdited(int index);
    void markWord(QLineEdit* word, bool invalid);
    void fail(const QString& message, QWidget* focus);
    int wordCount() const;
    QString mnemonic() const;

private:
    Ui::Recover *ui;
    QList<QLabel*> numbers;
    QList<QLineEdit*> words;
};

#endif //FIRO_RECOVER_H
