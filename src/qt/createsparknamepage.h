#ifndef _QT_CREATESPARKNAMEPAGE_H
#define _QT_CREATESPARKNAMEPAGE_H

#include <QDialog>

namespace Ui {
    class CreateSparkNamePage;
}

class PlatformStyle;

class CreateSparkNamePage : public QDialog
{
    Q_OBJECT

public:
    explicit CreateSparkNamePage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~CreateSparkNamePage();

private:
    Ui::CreateSparkNamePage *ui;

};

#endif // _QT_CREATESPARKNAMEPAGE_H