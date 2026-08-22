// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receiverequestdialog.h"
#include "ui_receiverequestdialog.h"

#include "bitcoinunits.h"
#include "guiconstants.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "walletmodel.h"

#include <QClipboard>
#include <QDrag>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QPixmap>
#include <QPushButton>
#if QT_VERSION < 0x050000
#include <QUrl>
#endif

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h" /* for USE_QRCODE */
#endif

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

QRImageWidget::QRImageWidget(QWidget *parent):
    QLabel(parent), contextMenu(0)
{
    contextMenu = new QMenu(this);
    QAction *saveImageAction = new QAction(tr("&Save Image..."), this);
    connect(saveImageAction, &QAction::triggered, this, &QRImageWidget::saveImage);
    contextMenu->addAction(saveImageAction);
    QAction *copyImageAction = new QAction(tr("&Copy Image"), this);
    connect(copyImageAction, &QAction::triggered, this, &QRImageWidget::copyImage);
    contextMenu->addAction(copyImageAction);
}

QImage QRImageWidget::exportImage()
{
    return GUIUtil::GetImage(this);
}

void QRImageWidget::mousePressEvent(QMouseEvent *event)
{
    if(event->button() == Qt::LeftButton && GUIUtil::HasPixmap(this))
    {
        event->accept();
        QMimeData *mimeData = new QMimeData;
        mimeData->setImageData(exportImage());

        QDrag *drag = new QDrag(this);
        drag->setMimeData(mimeData);
        drag->exec();
    } else {
        QLabel::mousePressEvent(event);
    }
}

void QRImageWidget::saveImage()
{
    if(!GUIUtil::HasPixmap(this))
        return;
    QString fn = GUIUtil::getSaveFileName(this, tr("Save QR Code"), QString(), tr("PNG Image (*.png)"), NULL);
    if (!fn.isEmpty())
    {
        exportImage().save(fn);
    }
}

void QRImageWidget::copyImage()
{
    if(!GUIUtil::HasPixmap(this))
        return;
    QApplication::clipboard()->setImage(exportImage());
}

void QRImageWidget::contextMenuEvent(QContextMenuEvent *event)
{
    if(!GUIUtil::HasPixmap(this))
        return;
    contextMenu->exec(event->globalPos());
}

ReceiveRequestDialog::ReceiveRequestDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveRequestDialog),
    model(0),
    walletModel(0)
{
    ui->setupUi(this);

#ifndef USE_QRCODE
    ui->btnSaveAs->setVisible(false);
    ui->lblQRCode->setVisible(false);
#endif

    connect(ui->btnSaveAs, &QPushButton::clicked, ui->lblQRCode, &QRImageWidget::saveImage);
    connect(ui->closeButton, &QPushButton::clicked, this, &QDialog::accept);

    connect(&GUIUtil::ThemeNotifier::instance(), &GUIUtil::ThemeNotifier::themeChanged,
            this, &ReceiveRequestDialog::applyTheme);
    applyTheme();
}

void ReceiveRequestDialog::applyTheme()
{
    setStyleSheet(GUIUtil::themed(QStringLiteral("QDialog { background: $BG; }")));
    ui->lblQRCode->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QLabel { background: $PANEL; border: 1px solid $BORDER; border-radius: 18px; color: $INK; }")));
    ui->outUri->setStyleSheet(GUIUtil::themed(QStringLiteral(
        "QTextEdit { background: $WINE_TINT; border: 1.5px solid $WINE; border-radius: 16px;"
        " padding: 14px 16px; color: $INK; }")));

    const QString secondaryButtonStyle = GUIUtil::secondaryButtonStyle();
    const QString primaryButtonStyle = GUIUtil::primaryButtonStyle();
    ui->btnCopyURI->setStyleSheet(secondaryButtonStyle);
    ui->btnCopyAddress->setStyleSheet(secondaryButtonStyle);
    ui->btnSaveAs->setStyleSheet(secondaryButtonStyle);
    ui->closeButton->setStyleSheet(primaryButtonStyle);

    update();
}

ReceiveRequestDialog::~ReceiveRequestDialog()
{
    delete ui;
}

void ReceiveRequestDialog::setModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;
    this->model = _walletModel ? _walletModel->getOptionsModel() : 0;

    if (model)
        connect(model, &OptionsModel::displayUnitChanged, this, &ReceiveRequestDialog::update);

    // update the display unit if necessary
    update();
}

void ReceiveRequestDialog::setInfo(const SendCoinsRecipient &_info)
{
    this->info = _info;
    update();
}

void ReceiveRequestDialog::update()
{
    if(!model || !walletModel)
        return;
    resize(width(), 600);
    QString target = info.label;
    if(target.isEmpty())
        target = info.address;
    setWindowTitle(tr("Request payment to %1").arg(target));

    QString uri = GUIUtil::formatBitcoinURI(info);
    ui->btnSaveAs->setEnabled(false);

    const GUIUtil::ThemeColors& tc = GUIUtil::themeColors();
    const QString captionStyle = QStringLiteral("color:%1; font-size:11px; font-weight:700;").arg(tc.wine);
    const QString valueStyle = QStringLiteral(
        "color:%1; font-family:'Menlo','Courier New',monospace; font-size:12px;").arg(tc.ink);
    const auto section = [&](const QString& caption, const QString& value) {
        return QStringLiteral("<p style=\"margin:0 0 4px 0;\"><span style=\"%1\">%2</span></p>"
                              "<p style=\"margin:0 0 14px 0;\"><span style=\"%3\">%4</span></p>")
            .arg(captionStyle, caption.toUpper(), valueStyle, value);
    };

    QString html = QStringLiteral("<html><body style=\"margin:0;\">");
    html += section(tr("Payment URI"), GUIUtil::HtmlEscape(uri));
    html += section(tr("Address"), GUIUtil::HtmlEscape(info.address));
    if (info.amount)
        html += section(tr("Amount"), BitcoinUnits::formatHtmlWithUnit(model->getDisplayUnit(), info.amount));
    if (!info.label.isEmpty())
        html += section(tr("Label"), GUIUtil::HtmlEscape(info.label));
    if (walletModel->validateAddress(info.address)) {
        html += section(tr("Address Type"), tr("transparent"));
    } else if (walletModel->validateSparkAddress(info.address)) {
        html += section(tr("Address Type"), tr("spark"));
    }
    if (!info.message.isEmpty())
        html += section(tr("Message"), GUIUtil::HtmlEscape(info.message));
    html += QStringLiteral("</body></html>");
    ui->outUri->setHtml(html);

#ifdef USE_QRCODE
    ui->lblQRCode->setText("");
    if(!uri.isEmpty())
    {
        // limit URI length
        if (uri.length() > MAX_URI_LENGTH)
        {
            ui->lblQRCode->setText(tr("Resulting URI too long, try to reduce the text for label / message."));
        } else {
            QRcode *code = QRcode_encodeString(uri.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
            if (!code)
            {
                ui->lblQRCode->setText(tr("Error encoding URI into QR Code."));
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

            QImage qrAddrImage = QImage(QR_IMAGE_SIZE, QR_IMAGE_SIZE+20, QImage::Format_RGB32);
            qrAddrImage.fill(0xffffff);
            QPainter painter(&qrAddrImage);
            painter.drawImage(0, 0, qrImage.scaled(QR_IMAGE_SIZE, QR_IMAGE_SIZE));
            QFont font = GUIUtil::fixedPitchFont();
            font.setPixelSize(12);
            painter.setFont(font);
            QRect paddedRect = qrAddrImage.rect();
            paddedRect.setHeight(QR_IMAGE_SIZE+12);
            if (info.address.length() > 34) {
                painter.drawText(paddedRect, Qt::AlignBottom|Qt::AlignCenter, info.address.left(16) + "..." + info.address.right(16));
            } else {
                painter.drawText(paddedRect, Qt::AlignBottom|Qt::AlignCenter, info.address);
            }
            painter.end();

            ui->lblQRCode->setPixmap(QPixmap::fromImage(qrAddrImage));
            ui->btnSaveAs->setEnabled(true);
        }
    }
#endif
}

void ReceiveRequestDialog::on_btnCopyURI_clicked()
{
    GUIUtil::setClipboard(GUIUtil::formatBitcoinURI(info));
}

void ReceiveRequestDialog::on_btnCopyAddress_clicked()
{
    GUIUtil::setClipboard(info.address);
}
