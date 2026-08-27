// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "optionsdialog.h"
#include "ui_optionsdialog.h"

#include "bitcoinunits.h"
#include "guitheme.h"
#include "guiutil.h"
#include "optionsmodel.h"

#include "validation.h" // for DEFAULT_SCRIPTCHECK_THREADS and MAX_SCRIPTCHECK_THREADS
#include "netbase.h"
#include "txdb.h" // for -dbcache defaults
#include "util.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h" // for CWallet::GetRequiredFee()
#include "spark/state.h"
#endif

#include <boost/thread.hpp>

#include <QDataWidgetMapper>
#include <QDir>
#include <QIntValidator>
#include <QLocale>
#include <QMessageBox>
#include <QScrollArea>
#include <QTimer>
#include <QVBoxLayout>

OptionsDialog::OptionsDialog(QWidget *parent, bool enableWallet) :
    QDialog(parent),
    ui(new Ui::OptionsDialog),
    model(0),
    mapper(0)
{
    ui->setupUi(this);

    ui->verticalLayout->removeWidget(ui->tabWidget);
    auto* optionsScrollContents = new QWidget(this);
    optionsScrollContents->setObjectName(QStringLiteral("optionsScrollContents"));
    auto* optionsScrollLayout = new QVBoxLayout(optionsScrollContents);
    optionsScrollLayout->setContentsMargins(0, 0, 0, 0);
    optionsScrollLayout->addWidget(ui->tabWidget);
    auto* optionsScroll = new QScrollArea(this);
    optionsScroll->setObjectName(QStringLiteral("optionsScroll"));
    optionsScroll->setWidgetResizable(true);
    optionsScroll->setFrameShape(QFrame::NoFrame);
    optionsScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    optionsScroll->setWidget(optionsScrollContents);
    optionsScroll->setStyleSheet(QStringLiteral(
        "QScrollArea#optionsScroll, QWidget#optionsScrollContents { background: transparent; border: none; }"));
    ui->verticalLayout->insertWidget(0, optionsScroll, 1);

    const QSize available = GUIUtil::availableScreenSize(this);
    resize(qMin(width(), qMax(1, available.width() - 40)),
           qMin(height(), qMax(1, available.height() - 40)));

    setStyleSheet(GUIUtil::themed(QStringLiteral(R"(
        QDialog { background: $BG; }
        QTabWidget::pane { background: $PANEL; border: 1px solid $BORDER; border-radius: 14px; top: -1px; }
        QTabBar::tab {
            background: transparent;
            color: $INK_SOFT;
            font-weight: 700;
            padding: 8px 14px;
            border: none;
        }
        QTabBar::tab:selected { color: $WINE; }
        QTabBar::tab:hover { color: $INK; }
        QGroupBox {
            background: $PANEL_SOFT;
            border: 1px solid $BORDER;
            border-radius: 12px;
            font-weight: 700;
            color: $INK;
            margin-top: 10px;
            padding-top: 12px;
        }
        QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 4px; color: $INK_SOFT; background-color: $PANEL; }
        QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 8px;
            padding: 4px 8px;
            color: $INK;
        }
        QSpinBox QLineEdit { %1 }
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid $WINE; }
        QCheckBox { color: $INK_SOFT; }
        QLabel#torStatusLabel { color: $INK_SOFT; }
        QPushButton {
            color: $INK;
            background: $PANEL;
            border: 1px solid $BORDER;
            border-radius: 10px;
            font-weight: 700;
            padding: 7px 16px;
        }
        QPushButton:hover:enabled { background: $PANEL_SOFT; border-color: $BORDER; }
        QPushButton:pressed { background: $PANEL_SOFT; }
        QPushButton#okButton {
            color: #FFFFFF;
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
            border: none;
        }
        QPushButton#okButton:hover:enabled {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                        stop:0 $WINE, stop:1 $WINE_DEEP);
        }
        QPushButton#okButton:pressed { background: $WINE_DEEP; }
    )")).arg(GUIUtil::spinBoxInnerLineEditReset()));

    /* Main elements init */
    ui->databaseCache->setMinimum(nMinDbCache);
    ui->databaseCache->setMaximum(nMaxDbCache);
    ui->threadsScriptVerif->setMinimum(-GetNumCores());
    ui->threadsScriptVerif->setMaximum(MAX_SCRIPTCHECK_THREADS);

    /* Network elements init */
#ifndef USE_UPNP
    ui->mapPortUpnp->setEnabled(false);
#endif

    ui->proxyIp->setEnabled(false);
    ui->proxyPort->setEnabled(false);
    ui->proxyPort->setValidator(new QIntValidator(1, 65535, this));

    ui->proxyIpTor->setEnabled(false);
    ui->proxyPortTor->setEnabled(false);
    ui->proxyPortTor->setValidator(new QIntValidator(1, 65535, this));

    connect(ui->connectSocks, &QPushButton::toggled, ui->proxyIp, &QWidget::setEnabled);
    connect(ui->connectSocks, &QPushButton::toggled, ui->proxyPort, &QWidget::setEnabled);
    connect(ui->connectSocks, &QPushButton::toggled, this, &OptionsDialog::updateProxyValidationState);

    connect(ui->connectSocksTor, &QPushButton::toggled, ui->proxyIpTor, &QWidget::setEnabled);
    connect(ui->connectSocksTor, &QPushButton::toggled, ui->proxyPortTor, &QWidget::setEnabled);
    connect(ui->connectSocksTor, &QPushButton::toggled, this, &OptionsDialog::updateProxyValidationState);

    /* Window elements init */
#ifdef Q_OS_MAC
    /* remove Window tab on Mac */
    ui->tabWidget->removeTab(ui->tabWidget->indexOf(ui->tabWindow));
#endif

    /* remove Wallet tab in case of -disablewallet */
    if (!enableWallet) {
        ui->tabWidget->removeTab(ui->tabWidget->indexOf(ui->tabWallet));
    }

    /* Display elements init */
    QDir translations(":translations");

    ui->bitcoinAtStartup->setToolTip(ui->bitcoinAtStartup->toolTip().arg(tr(PACKAGE_NAME)));
    ui->bitcoinAtStartup->setText(ui->bitcoinAtStartup->text().arg(tr(PACKAGE_NAME)));

    ui->lang->setToolTip(ui->lang->toolTip().arg(tr(PACKAGE_NAME)));
    ui->lang->addItem(QString("(") + tr("default") + QString(")"), QVariant(""));
    for (const QString &langStr : translations.entryList())
    {
        QLocale locale(langStr);

        /** check if the locale name consists of 2 parts (language_country) */
        if(langStr.contains("_"))
        {
#if QT_VERSION >= 0x040800
            /** display language strings as "native language - native country (locale name)", e.g. "Deutsch - Deutschland (de)" */
#if QT_VERSION >= 0x060000
            ui->lang->addItem(locale.nativeLanguageName() + QString(" - ") + locale.nativeTerritoryName() + QString(" (") + langStr + QString(")"), QVariant(langStr));
#else
            ui->lang->addItem(locale.nativeLanguageName() + QString(" - ") + locale.nativeCountryName() + QString(" (") + langStr + QString(")"), QVariant(langStr));
#endif
#else
            /** display language strings as "language - country (locale name)", e.g. "German - Germany (de)" */
            ui->lang->addItem(QLocale::languageToString(locale.language()) + QString(" - ") + QLocale::countryToString(locale.country()) + QString(" (") + langStr + QString(")"), QVariant(langStr));
#endif
        }
        else
        {
#if QT_VERSION >= 0x040800
            /** display language strings as "native language (locale name)", e.g. "Deutsch (de)" */
            ui->lang->addItem(locale.nativeLanguageName() + QString(" (") + langStr + QString(")"), QVariant(langStr));
#else
            /** display language strings as "language (locale name)", e.g. "German (de)" */
            ui->lang->addItem(QLocale::languageToString(locale.language()) + QString(" (") + langStr + QString(")"), QVariant(langStr));
#endif
        }
    }
#if QT_VERSION >= 0x040700
    ui->thirdPartyTxUrls->setPlaceholderText("https://example.com/tx/%s");
#endif

    ui->unit->setModel(new BitcoinUnits(this));

    /* Widget-to-option mapper */
    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
    mapper->setOrientation(Qt::Vertical);

    /* setup/change UI elements when proxy IPs are invalid/valid */
    ui->proxyIp->setCheckValidator(new ProxyAddressValidator(parent));
    ui->proxyIpTor->setCheckValidator(new ProxyAddressValidator(parent));
    connect(ui->proxyIp, &QValidatedLineEdit::validationDidChange, this, &OptionsDialog::updateProxyValidationState);
    connect(ui->proxyIpTor, &QValidatedLineEdit::validationDidChange, this, &OptionsDialog::updateProxyValidationState);
    connect(ui->proxyPort, &QLineEdit::textChanged, this, &OptionsDialog::updateProxyValidationState);
    connect(ui->proxyPortTor, &QLineEdit::textChanged, this, &OptionsDialog::updateProxyValidationState);
}

OptionsDialog::~OptionsDialog()
{
    delete ui;
}

void OptionsDialog::setModel(OptionsModel *_model)
{
    this->model = _model;

    if(_model)
    {
        /* check if client restart is needed and show persistent message */
        if (_model->isRestartRequired())
            showRestartWarning(true);

        QString strLabel = _model->getOverriddenByCommandLine();
        if (strLabel.isEmpty())
            strLabel = tr("none");
        ui->overriddenByCommandLineLabel->setText(strLabel);

        mapper->setModel(_model);
        setMapper();
        mapper->toFirst();

        updateDefaultProxyNets();
        updateTorStatusLabel();
    }

    /* warn when one of the following settings changes by user action (placed here so init via mapper doesn't trigger them) */

    /* Main */
    connect(ui->databaseCache, qOverload<int>(&QSpinBox::valueChanged), this, &OptionsDialog::showRestartWarning);
    connect(ui->threadsScriptVerif, qOverload<int>(&QSpinBox::valueChanged), this, &OptionsDialog::showRestartWarning);
    /* Wallet */
    connect(ui->spendZeroConfChange, &QCheckBox::clicked, this, &OptionsDialog::showRestartWarning);
#ifdef ENABLE_WALLET
    connect(ui->reindexSpark, &QCheckBox::clicked, this, &OptionsDialog::handleEnabledZapChanged);
#endif
    /* Network */
    connect(ui->allowIncoming, &QCheckBox::clicked, this, &OptionsDialog::showRestartWarning);
    connect(ui->connectSocks, &QCheckBox::clicked, this, &OptionsDialog::showRestartWarning);
    connect(ui->connectSocksTor, &QCheckBox::clicked, this, &OptionsDialog::showRestartWarning);
    connect(ui->checkboxEnabledTor, &QCheckBox::clicked, this, &OptionsDialog::showRestartWarning);
    connect(ui->checkboxEnabledTor, &QCheckBox::clicked, this, &OptionsDialog::updateTorStatusLabel);
    /* Display */
    connect(ui->lang, qOverload<>(&QValueComboBox::valueChanged), [this]{ showRestartWarning(); });
    connect(ui->thirdPartyTxUrls, &QLineEdit::textChanged, [this]{ showRestartWarning(); });
}

void OptionsDialog::setMapper()
{
    /* Main */
    mapper->addMapping(ui->bitcoinAtStartup, OptionsModel::StartAtStartup);
    mapper->addMapping(ui->threadsScriptVerif, OptionsModel::ThreadsScriptVerif);
    mapper->addMapping(ui->databaseCache, OptionsModel::DatabaseCache);

    /* Wallet */
    mapper->addMapping(ui->spendZeroConfChange, OptionsModel::SpendZeroConfChange);
#ifdef ENABLE_WALLET
    mapper->addMapping(ui->reindexSpark, OptionsModel::ReindexSpark);
#endif
    mapper->addMapping(ui->coinControlFeatures, OptionsModel::CoinControlFeatures);
    mapper->addMapping(ui->autoAnonymize, OptionsModel::AutoAnonymize);
    mapper->addMapping(ui->fSplit, OptionsModel::Split);
    mapper->addMapping(ui->sparkPage, OptionsModel::SparkPage);
#ifdef ENABLE_WALLET
    if (!spark::IsSparkAllowed()) {
        ui->sparkGroupBox->setVisible(false);
    }
#else
    ui->sparkGroupBox->setVisible(false);
#endif
    /* Network */
    mapper->addMapping(ui->mapPortUpnp, OptionsModel::MapPortUPnP);
    mapper->addMapping(ui->allowIncoming, OptionsModel::Listen);

    mapper->addMapping(ui->connectSocks, OptionsModel::ProxyUse);
    mapper->addMapping(ui->proxyIp, OptionsModel::ProxyIP);
    mapper->addMapping(ui->proxyPort, OptionsModel::ProxyPort);

    mapper->addMapping(ui->connectSocksTor, OptionsModel::ProxyUseTor);
    mapper->addMapping(ui->proxyIpTor, OptionsModel::ProxyIPTor);
    mapper->addMapping(ui->proxyPortTor, OptionsModel::ProxyPortTor);

    mapper->addMapping(ui->checkboxEnabledTor, OptionsModel::TorSetup);

    /* Window */
#ifndef Q_OS_MAC
    mapper->addMapping(ui->hideTrayIcon, OptionsModel::HideTrayIcon);
    mapper->addMapping(ui->minimizeToTray, OptionsModel::MinimizeToTray);
    mapper->addMapping(ui->minimizeOnClose, OptionsModel::MinimizeOnClose);
#endif

    /* Display */
    mapper->addMapping(ui->lang, OptionsModel::Language);
    mapper->addMapping(ui->unit, OptionsModel::DisplayUnit);
    mapper->addMapping(ui->thirdPartyTxUrls, OptionsModel::ThirdPartyTxUrls);
}

void OptionsDialog::setOkButtonState(bool fState)
{
    ui->okButton->setEnabled(fState);
}

void OptionsDialog::on_resetButton_clicked()
{
    if(model)
    {
        // confirmation dialog
        QMessageBox::StandardButton btnRetVal = QMessageBox::question(this, tr("Confirm options reset"),
            tr("Client restart required to activate changes.") + "<br><br>" + tr("Client will be shut down. Do you want to proceed?"),
            QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel);

        if(btnRetVal == QMessageBox::Cancel)
            return;

        /* reset all options and close GUI */
        model->Reset();
        QApplication::quit();
    }
}

void OptionsDialog::on_okButton_clicked()
{
    mapper->submit();
    accept();
    updateDefaultProxyNets();
}

void OptionsDialog::on_cancelButton_clicked()
{
    reject();
}

void OptionsDialog::on_hideTrayIcon_stateChanged(int fState)
{
    if(fState)
    {
        ui->minimizeToTray->setChecked(false);
        ui->minimizeToTray->setEnabled(false);
    }
    else
    {
        ui->minimizeToTray->setEnabled(true);
    }
}
void OptionsDialog::handleEnabledZapChanged()
{
#ifdef ENABLE_WALLET
    if (ui->reindexSpark->isChecked()) {
        QMessageBox::StandardButton retval = QMessageBox::warning(this, tr("Confirm Spark reindex"),
            tr("Warning: On restart, this setting will wipe your transaction list, reindex the blockchain, and restore wallet data from your seed. Spark mint records are cleared and rebuilt from the chain. This will likely take a few hours. Are you sure?"),
            QMessageBox::Yes | QMessageBox::Cancel,
            QMessageBox::Cancel);
        if (retval == QMessageBox::Cancel) {
            ui->reindexSpark->setChecked(false);
        } else {
            showRestartWarning();
        }
    } else
#endif
    {
        clearStatusLabel();
    }
}

void OptionsDialog::updateTorStatusLabel()
{
    const bool runningWithTor = GetBoolArg("-torsetup", DEFAULT_TOR_SETUP);
    const bool overridden = model && model->getOverriddenByCommandLine().contains(QLatin1String("-torsetup"));
    if (overridden) {
        ui->checkboxEnabledTor->setEnabled(false);
        ui->torStatusLabel->setText(runningWithTor
            ? tr("Tor quickstart is enabled for this session by -torsetup. It cannot be changed here.")
            : tr("Tor quickstart is disabled for this session by -torsetup. It cannot be changed here."));
        return;
    }

    ui->checkboxEnabledTor->setEnabled(true);

    const bool checked = ui->checkboxEnabledTor->isChecked();

    if (checked && runningWithTor) {
        ui->torStatusLabel->setText(tr("Tor quickstart is enabled for this session."));
    } else if (checked && !runningWithTor) {
        ui->torStatusLabel->setText(tr("Tor quickstart is enabled. Restart the client to apply this change."));
    } else if (!checked && runningWithTor) {
        ui->torStatusLabel->setText(tr("Tor quickstart is disabled. Restart the client to apply this change."));
    } else {
        ui->torStatusLabel->setText(tr("Tor quickstart is disabled."));
    }
}

void OptionsDialog::showRestartWarning(bool fPersistent)
{
    ui->statusLabel->setStyleSheet("QLabel { color: red; }");

    if(fPersistent)
    {
        ui->statusLabel->setText(tr("Client restart required to activate changes."));
    }
    else
    {
        ui->statusLabel->setText(tr("This change would require a client restart."));
        // clear non-persistent status label after 10 seconds
        // Todo: should perhaps be a class attribute, if we extend the use of statusLabel
        QTimer::singleShot(10000, this, &OptionsDialog::clearStatusLabel);
    }
}

void OptionsDialog::clearStatusLabel()
{
    ui->statusLabel->clear();
    if (model && model->isRestartRequired()) {
        showRestartWarning(true);
    }
}

void OptionsDialog::updateProxyValidationState()
{
    QValidatedLineEdit *pUiProxyIp = ui->proxyIp;
    QValidatedLineEdit *otherProxyWidget = (pUiProxyIp == ui->proxyIpTor) ? ui->proxyIp : ui->proxyIpTor;
    if (pUiProxyIp->isValid() && (!ui->proxyPort->isEnabled() || ui->proxyPort->text().toInt() > 0) && (!ui->proxyPortTor->isEnabled() || ui->proxyPortTor->text().toInt() > 0))
    {
        setOkButtonState(otherProxyWidget->isValid()); //only enable ok button if both proxys are valid
        clearStatusLabel();
    }
    else
    {
        setOkButtonState(false);
        ui->statusLabel->setStyleSheet("QLabel { color: red; }");
        ui->statusLabel->setText(tr("The supplied proxy address is invalid."));
    }
}

void OptionsDialog::updateDefaultProxyNets()
{
    proxyType proxy;
    std::string strProxy;
    QString strDefaultProxyGUI;

    GetProxy(NET_IPV4, proxy);
    strProxy = proxy.proxy.ToStringIP() + ":" + proxy.proxy.ToStringPort();
    strDefaultProxyGUI = ui->proxyIp->text() + ":" + ui->proxyPort->text();
    (strProxy == strDefaultProxyGUI.toStdString()) ? ui->proxyReachIPv4->setChecked(true) : ui->proxyReachIPv4->setChecked(false);

    GetProxy(NET_IPV6, proxy);
    strProxy = proxy.proxy.ToStringIP() + ":" + proxy.proxy.ToStringPort();
    strDefaultProxyGUI = ui->proxyIp->text() + ":" + ui->proxyPort->text();
    (strProxy == strDefaultProxyGUI.toStdString()) ? ui->proxyReachIPv6->setChecked(true) : ui->proxyReachIPv6->setChecked(false);

    GetProxy(NET_ONION, proxy);
    strProxy = proxy.proxy.ToStringIP() + ":" + proxy.proxy.ToStringPort();
    strDefaultProxyGUI = ui->proxyIp->text() + ":" + ui->proxyPort->text();
    (strProxy == strDefaultProxyGUI.toStdString()) ? ui->proxyReachTor->setChecked(true) : ui->proxyReachTor->setChecked(false);
}

ProxyAddressValidator::ProxyAddressValidator(QObject *parent) :
QValidator(parent)
{
}

QValidator::State ProxyAddressValidator::validate(QString &input, int &pos) const
{
    Q_UNUSED(pos);
    // Validate the proxy
    CService serv(LookupNumeric(input.toStdString().c_str(), 9050));
    proxyType addrProxy = proxyType(serv, true);
    if (addrProxy.IsValid())
        return QValidator::Acceptable;

    return QValidator::Invalid;
}
