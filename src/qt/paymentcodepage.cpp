#include "paymentcodepage.h"
#include "ui_paymentcodepage.h"

#include "activeznode.h"
#include "clientmodel.h"
#include "init.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "sync.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "recentpaymentcodetransactionstablemodel.h"

#include <QTimer>
#include <QMessageBox>
#include <QImage>
#include <QFont>
#include <QPixmap>
#include <QClipboard>
#include <QHeaderView>

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h" /* for USE_QRCODE */
#endif

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

#include "bip47/PaymentCode.h"
#include "bip47/Bip47Wallet.h"

#define PCODE_QR_IMAGE_SIZE 150

PaymentcodePage::PaymentcodePage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PaymentcodePage),
    columnResizingFixer(0),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);
    contextMenu = new QMenu();
    QString paymentCodeStr = QString::fromStdString(pbip47WalletMain->getPaymentCode());
    ui->paymentcodeLabel->setText(paymentCodeStr);
    QString notificationAddress = QString::fromStdString(std::string("Notification Address is ") + pbip47WalletMain->getNotifiactionAddress());
    ui->paymentcodeLabel->setToolTip(notificationAddress);
    


#ifdef USE_QRCODE
    ui->paymentcodeQRCode->setText("");
    if(!paymentCodeStr.isEmpty())
    {
        // limit URI length
        if (paymentCodeStr.length() > MAX_URI_LENGTH)
        {
            ui->paymentcodeQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QRcode *code = QRcode_encodeString(paymentCodeStr.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code)
            {
                ui->paymentcodeQRCode->setText(tr("Error encoding URI into QR Code."));
                return;
            }
            QImage qrImage = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
            qrImage.fill(0xffffff);
            unsigned char *p = code->data;
            for (int y = 0; y < code->width; y++)
            {
                for (int x = 0; x < code->width; x++)
                {
                    qrImage.setPixel(x + 4, y + 4, ((*p & 1) ? 0x0 : 0xffffff));
                    p++;
                }
            }
            QRcode_free(code);

            QImage qrAddrImage = QImage(PCODE_QR_IMAGE_SIZE, PCODE_QR_IMAGE_SIZE, QImage::Format_RGB32);
            qrAddrImage.fill(0xffffff);
            QPainter painter(&qrAddrImage);
            painter.drawImage(0, 0, qrImage.scaled(PCODE_QR_IMAGE_SIZE, PCODE_QR_IMAGE_SIZE));
            painter.end();

            ui->paymentcodeQRCode->setPixmap(QPixmap::fromImage(qrAddrImage));
            // ui->btnSaveAs->setEnabled(true);
        }
    }
#endif
}

PaymentcodePage::~PaymentcodePage()
{
    delete ui;
}

void PaymentcodePage::copy_button_clicked() {
    
}

void PaymentcodePage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

void PaymentcodePage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;

        if(model && model->getOptionsModel())
    {
        // connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        QTableView* tableView = ui->notificationTransactionsView;

        RecentPCodeTransactionsTableModel *pmodel = model->getRecentPCodeTransactionsTableModel();

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(pmodel);
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentPCodeTransactionsTableModel::RPCode, 600);
        tableView->setColumnWidth(RecentPCodeTransactionsTableModel::Fee, 130);
        tableView->setColumnWidth(RecentPCodeTransactionsTableModel::Timestamp, 150);

        // QFont font("Arial", 20, QFont::Bold);
        // tableView->horizontalHeader()->setFont( font );
        // tableView->verticalHeader()->resizeSections(QHeaderView::ResizeToContents);

        tableView->horizontalHeader()->setSectionResizeMode(RecentPCodeTransactionsTableModel::RPCode, QHeaderView::Stretch);
        tableView->horizontalHeader()->setSectionResizeMode(RecentPCodeTransactionsTableModel::Fee, QHeaderView::Interactive);
        tableView->horizontalHeader()->setSectionResizeMode(RecentPCodeTransactionsTableModel::Timestamp, QHeaderView::Interactive);
        tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
        // columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, 150, 300, this);
    }

    
    
}

void PaymentcodePage::showContextMenu(const QPoint &point)
{
    contextMenu->exec(QCursor::pos());
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void PaymentcodePage::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    // columnResizingFixer->stretchColumnWidth(RecentPCodeTransactionsTableModel::RPCode);

}
