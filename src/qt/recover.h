#ifndef FIRO_RECOVER_H
#define FIRO_RECOVER_H

#include <QDialog>
#include <QList>
#include <QThread>

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

    static bool askRecover(bool& newWallet);

Q_SIGNALS:
    void stopThread();

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
    QThread *thread;
    QList<QLabel*> numbers;
    QList<QLineEdit*> words;
};

#endif //FIRO_RECOVER_H
