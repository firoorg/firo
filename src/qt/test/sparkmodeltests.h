#ifndef FIRO_QT_TEST_SPARKMODELTESTS_H
#define FIRO_QT_TEST_SPARKMODELTESTS_H

#include <QObject>

class SparkModelTests : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void importRetries_data();
    void importRetries();
    void addressBookDefers();
    void autoMintDefers();
};

#endif // FIRO_QT_TEST_SPARKMODELTESTS_H
