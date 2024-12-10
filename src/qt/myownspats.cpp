#include "myownspats.h"
#include "ui_myownspats.h"

MyOwnSpats::MyOwnSpats(const PlatformStyle* platformStyle, QWidget* parent) :
    QWidget(parent),
    ui_(std::make_unique<Ui::MyOwnSpats>())
{
    ui_->setupUi(this);
}

MyOwnSpats::~MyOwnSpats() {}

void MyOwnSpats::setClientModel(ClientModel* model)
{
    if (client_model_) {
        // Disconnect signals from old model, if any
    }
    client_model_ = model;
    if (model) {
        // Connect necessary signals for UI updates, if any
    }
}

void MyOwnSpats::setWalletModel(WalletModel* model)
{
    if (wallet_model_) {
        // Disconnect signals from old model, if any
    }
    wallet_model_ = model;
    if (model) {
        // Connect necessary signals for UI updates, if any
    }
}

void MyOwnSpats::resizeEvent(QResizeEvent* event) 
{
    QWidget::resizeEvent(event);
    adjustTextSize(width(), height());
}

void MyOwnSpats::adjustTextSize(int width,int height){

    const double fontSizeScalingFactor = 70.0;
    int baseFontSize = std::min(width, height) / fontSizeScalingFactor;
    int fontSize = std::min(15, std::max(12, baseFontSize));
    QFont font = this->font();
    font.setPointSize(fontSize);

    // Set font size for all labels
    ui_->label_filter_2->setFont(font);
    ui_->label_count_2->setFont(font);
    ui_->countLabel->setFont(font);
    ui_->tableWidgetMyOwnSpats->setFont(font);
    ui_->tableWidgetMyOwnSpats->horizontalHeader()->setFont(font);
    ui_->tableWidgetMyOwnSpats->verticalHeader()->setFont(font);
}
