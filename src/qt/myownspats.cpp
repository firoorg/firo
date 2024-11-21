#include "myownspats.h"
#include "ui_myownspats.h"

MyOwnSpats::MyOwnSpats(const PlatformStyle* platformStyle, QWidget* parent) :
    QWidget(parent),
    ui(std::make_unique<Ui::MyOwnSpats>())
{
    ui->setupUi(this);
}

MyOwnSpats::~MyOwnSpats() {}

void MyOwnSpats::setClientModel(ClientModel* model)
{
    this->clientModel = model;
}

void MyOwnSpats::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void MyOwnSpats::resizeEvent(QResizeEvent* event) 
{
    QWidget::resizeEvent(event);
}

void MyOwnSpats::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 70.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    // Set font size for all labels
    ui->label_filter_2->setFont(font);
    ui->label_count_2->setFont(font);
    ui->countLabel->setFont(font);
    ui->tableWidgetMyOwnSpats->setFont(font);
    ui->tableWidgetMyOwnSpats->horizontalHeader()->setFont(font);
    ui->tableWidgetMyOwnSpats->verticalHeader()->setFont(font);
}
