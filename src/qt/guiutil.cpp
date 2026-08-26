// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "guiutil.h"

#include "bitcoinaddressvalidator.h"
#include "bitcoinunits.h"
#include "guitheme.h"
#include "qvalidatedlineedit.h"
#include "rosenbridge.h"
#include "walletmodel.h"

#include "amount.h"
#include "primitives/transaction.h"
#include "init.h"
#include "logging.h"
#include "policy/policy.h"
#include "protocol.h"
#include "script/script.h"
#include "script/standard.h"
#include "util.h"

#ifdef WIN32
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501
#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501
#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "shellapi.h"
#include "shlobj.h"
#include "shlwapi.h"
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#if BOOST_FILESYSTEM_VERSION >= 3
#include <boost/filesystem/detail/utf8_codecvt_facet.hpp>
#endif
#include <boost/scoped_array.hpp>

#include <exception>
#include <thread>

#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QScreen>
#include <QDoubleValidator>
#include <QEventLoop>
#include <QFileDialog>
#include <QFont>
#include <QLineEdit>
#include <QRegularExpression>
#include <QSettings>
#include <QStandardPaths>
#include <QTextDocument> // for Qt::mightBeRichText
#include <QThread>
#include <QMouseEvent>
#include <QTextStream>

#if QT_VERSION < 0x050000
#include <QUrl>
#else
#include <QUrlQuery>
#endif

#if QT_VERSION >= 0x50200
#include <QFontDatabase>
#endif

#if BOOST_FILESYSTEM_VERSION >= 3
static boost::filesystem::detail::utf8_codecvt_facet utf8;
#endif

#if defined(Q_OS_MAC)
extern double NSAppKitVersionNumber;
#if !defined(NSAppKitVersionNumber10_8)
#define NSAppKitVersionNumber10_8 1187
#endif
#if !defined(NSAppKitVersionNumber10_9)
#define NSAppKitVersionNumber10_9 1265
#endif
#endif

namespace GUIUtil {

static QString stylesheetDirectory = ":css";
static QString firoTheme = "firoTheme";
static CCriticalSection cs_css;

void runWalletOperation(const std::function<void()>& operation)
{
    std::exception_ptr exception;
    QEventLoop waitLoop;
    std::thread worker([&] {
        try {
            operation();
        } catch (...) {
            exception = std::current_exception();
        }
        QMetaObject::invokeMethod(&waitLoop, &QEventLoop::quit, Qt::QueuedConnection);
    });
    QApplication::setOverrideCursor(Qt::WaitCursor);
    struct Cleanup {
        std::thread& worker;
        ~Cleanup()
        {
            if (worker.joinable())
                worker.join();
            QApplication::restoreOverrideCursor();
        }
    } cleanup{worker};
    waitLoop.exec(QEventLoop::ExcludeUserInputEvents);
    worker.join();
    if (exception)
        std::rethrow_exception(exception);
}

QString dateTimeStr(const QDateTime &date)
{
    return  QLocale::system().toString(date.date(), QLocale::ShortFormat) + QString(" ") + date.toString("hh:mm");
}

QString dateTimeStr(qint64 nTime)
{
    return dateTimeStr(QDateTime::fromSecsSinceEpoch((qint32)nTime));
}

QFont fixedPitchFont()
{
#if QT_VERSION >= 0x50200
    return QFontDatabase::systemFont(QFontDatabase::FixedFont);
#else
    QFont font("Monospace");
#if QT_VERSION >= 0x040800
    font.setStyleHint(QFont::Monospace);
#else
    font.setStyleHint(QFont::TypeWriter);
#endif
    return font;
#endif
}

// Just some dummy data to generate an convincing random-looking (but consistent) address
static const uint8_t dummydata[] = {0xeb,0x15,0x23,0x1d,0xfc,0xeb,0x60,0x92,0x58,0x86,0xb6,0x7d,0x06,0x52,0x99,0x92,0x59,0x15,0xae,0xb1,0x72,0xc0,0x66,0x47};

// Generate a dummy address with invalid CRC, starting with the network prefix.
static std::string DummyAddress(const CChainParams &params)
{
    std::vector<unsigned char> sourcedata = params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
    sourcedata.insert(sourcedata.end(), dummydata, dummydata + sizeof(dummydata));
    for(int i=0; i<256; ++i) { // Try every trailing byte
        std::string s = EncodeBase58(sourcedata.data(), sourcedata.data() + sourcedata.size());
        if (!CBitcoinAddress(s).IsValid())
            return s;
        sourcedata[sourcedata.size()-1] += 1;
    }
    return "";
}

void setupAddressWidget(QValidatedLineEdit *widget, QWidget *parent, bool allowPaymentURI)
{
    parent->setFocusProxy(widget);

    widget->setFont(fixedPitchFont());
#if QT_VERSION >= 0x040700
    // We don't want translators to use own addresses in translations
    // and this is the only place, where this address is supplied.
    widget->setPlaceholderText(QObject::tr("Enter a Firo address (e.g. %1)").arg(
        QString::fromStdString(DummyAddress(Params()))) +
        QObject::tr(" or a payment code") + QObject::tr(" or a Firo spark address (e.g. pr1cjgedy25xhr4fmzx8cm5gf940v5j2482m94uaa0yguxxw2yrel0f0hyjesg77px7at47f4s3jy8hthmyr6ajhvn025yp28fyuwzvar0gcc7p27rvttn2tyl9ejwthjpaavlmy3cm3sysz)"));
#endif
    widget->setValidator(new BitcoinAddressEntryValidator(parent, allowPaymentURI));
    widget->setCheckValidator(new BitcoinAddressCheckValidator(parent));
}

void setupAmountWidget(QLineEdit *widget, QWidget *parent)
{
    QDoubleValidator *amountValidator = new QDoubleValidator(parent);
    amountValidator->setDecimals(8);
    amountValidator->setBottom(0.0);
    widget->setValidator(amountValidator);
    widget->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
}

bool parseBitcoinURI(const QUrl &uri, SendCoinsRecipient *out)
{
    // return if URI is not valid or is no firo: URI
    if(!uri.isValid() || uri.scheme().compare(QStringLiteral("firo"), Qt::CaseInsensitive) != 0)
        return false;

    SendCoinsRecipient rv;
    rv.address = uri.path();
    // Trim any following forward slash which may have been added by the OS
    if (rv.address.endsWith("/")) {
        rv.address.truncate(rv.address.length() - 1);
    }
    rv.amount = 0;

#if QT_VERSION < 0x050000
    QList<QPair<QString, QString> > items = uri.queryItems();
#else
    QUrlQuery uriQuery(uri);
    QList<QPair<QString, QString> > items = uriQuery.queryItems();
#endif
    static const QRegularExpression DECIMAL_AMOUNT(QStringLiteral("\\A[0-9]+(?:\\.[0-9]{1,8})?\\z"));
    QList<QString> amounts;
    bool opReturnSeen = false;
    for (const auto& item : items)
    {
        QString key = item.first;
        bool fShouldReturnFalse = false;
        if (key.startsWith("req-"))
        {
            key.remove(0, 4);
            fShouldReturnFalse = true;
        }

        if (key == "label")
        {
            rv.label = item.second;
            fShouldReturnFalse = false;
        }
        else if (key == "message")
        {
            rv.message = item.second;
            fShouldReturnFalse = false;
        }
        else if (key == "amount")
        {
            amounts.append(item.second);
            fShouldReturnFalse = false;
        }
        else if (key == "op_return")
        {
            if (opReturnSeen || !RosenBridge::ParseHex(item.second, &rv.opReturnData)) {
                return false;
            }
            opReturnSeen = true;
            fShouldReturnFalse = false;
        }

        if (fShouldReturnFalse)
            return false;
    }

    if (opReturnSeen) {
        // Rosen emits decimal FIRO. Parse exactly once to avoid treating its
        // decimal value as an atomic-unit amount a second time.
        if (amounts.size() != 1 || !DECIMAL_AMOUNT.match(amounts.front()).hasMatch() ||
            !BitcoinUnits::parse(BitcoinUnits::BTC, amounts.front(), &rv.amount) ||
            !MoneyRange(rv.amount) || rv.amount <= 0) {
            return false;
        }
    } else {
        // Preserve the historical behavior of ordinary Firo payment URIs.
        for (const QString& amount : amounts) {
            if (!amount.isEmpty() && !BitcoinUnits::parse(BitcoinUnits::BTC, amount, &rv.amount)) {
                return false;
            }
        }
    }
    if(out)
    {
        *out = rv;
    }
    return true;
}

bool parseBitcoinURI(QString uri, SendCoinsRecipient *out)
{
    // Convert firo:// to firo:
    //
    //    Cannot handle this later, because firo:// will cause Qt to see the part after // as host,
    //    which will lower-case it (and thus invalidate the address).
    if(uri.startsWith("firo://", Qt::CaseInsensitive))
    {
        uri.replace(0, 7, "firo:");
    }
    QUrl uriInstance(uri);
    return parseBitcoinURI(uriInstance, out);
}

QString formatBitcoinURI(const SendCoinsRecipient &info)
{
    QString ret = QString("firo:%1").arg(info.address);
    int paramCount = 0;

    if (info.amount)
    {
        ret += QString("?amount=%1").arg(BitcoinUnits::format(BitcoinUnits::BTC, info.amount, false, BitcoinUnits::separatorNever));
        paramCount++;
    }

    if (!info.label.isEmpty())
    {
        QString lbl(QUrl::toPercentEncoding(info.label));
        ret += QString("%1label=%2").arg(paramCount == 0 ? "?" : "&").arg(lbl);
        paramCount++;
    }

    if (!info.message.isEmpty())
    {
        QString msg(QUrl::toPercentEncoding(info.message));
        ret += QString("%1message=%2").arg(paramCount == 0 ? "?" : "&").arg(msg);
        paramCount++;
    }

    if (!info.opReturnData.empty())
    {
        ret += QString("%1op_return=%2").arg(paramCount == 0 ? "?" : "&", RosenBridge::HexStr(info.opReturnData));
    }

    return ret;
}

bool isDust(const QString& address, const CAmount& amount)
{
    CTxDestination dest = CBitcoinAddress(address.toStdString()).Get();
    CScript script = GetScriptForDestination(dest);
    CTxOut txOut(amount, script);
    return txOut.IsDust(dustRelayFee);
}

QString HtmlEscape(const QString& str, bool fMultiLine)
{
#if QT_VERSION < 0x050000
    QString escaped = Qt::escape(str);
#else
    QString escaped = str.toHtmlEscaped();
#endif
    if(fMultiLine)
    {
        escaped = escaped.replace("\n", "<br>\n");
    }
    return escaped;
}

QString HtmlEscape(const std::string& str, bool fMultiLine)
{
    return HtmlEscape(QString::fromStdString(str), fMultiLine);
}

void copyEntryData(QAbstractItemView *view, int column, int role)
{
    if(!view || !view->selectionModel())
        return;
    QModelIndexList selection = view->selectionModel()->selectedRows(column);

    if(!selection.isEmpty())
    {
        // Copy first item
        setClipboard(selection.at(0).data(role).toString());
    }
}

QList<QModelIndex> getEntryData(QAbstractItemView *view, int column)
{
    if(!view || !view->selectionModel())
        return QList<QModelIndex>();
    return view->selectionModel()->selectedRows(column);
}

QString ExtractFirstSuffixFromFilter(const QString& filter)
{
    QRegularExpression filter_re(QStringLiteral(".* \\(\\*\\.(.*)[ \\)]"), QRegularExpression::InvertedGreedinessOption);
    QString suffix;
    QRegularExpressionMatch m = filter_re.match(filter);
    if (m.hasMatch()) {
        suffix = m.captured(1);
    }
    return suffix;
}

QString getSaveFileName(QWidget *parent, const QString &caption, const QString &dir,
    const QString &filter,
    QString *selectedSuffixOut)
{
    QString selectedFilter;
    QString myDir;
    if(dir.isEmpty()) // Default to user documents location
    {
#if QT_VERSION < 0x050000
        myDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
        myDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    }
    else
    {
        myDir = dir;
    }
    /* Directly convert path to native OS path separators */
    QString result = QDir::toNativeSeparators(QFileDialog::getSaveFileName(parent, caption, myDir, filter, &selectedFilter));

    QString selectedSuffix = ExtractFirstSuffixFromFilter(selectedFilter);

    /* Add suffix if needed */
    QFileInfo info(result);
    if(!result.isEmpty())
    {
        if(info.suffix().isEmpty() && !selectedSuffix.isEmpty())
        {
            /* No suffix specified, add selected suffix */
            if(!result.endsWith("."))
                result.append(".");
            result.append(selectedSuffix);
        }
    }

    /* Return selected suffix if asked to */
    if(selectedSuffixOut)
    {
        *selectedSuffixOut = selectedSuffix;
    }
    return result;
}

QString getOpenFileName(QWidget *parent, const QString &caption, const QString &dir,
    const QString &filter,
    QString *selectedSuffixOut)
{
    QString selectedFilter;
    QString myDir;
    if(dir.isEmpty()) // Default to user documents location
    {
#if QT_VERSION < 0x050000
        myDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
        myDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif
    }
    else
    {
        myDir = dir;
    }
    /* Directly convert path to native OS path separators */
    QString result = QDir::toNativeSeparators(QFileDialog::getOpenFileName(parent, caption, myDir, filter, &selectedFilter));

    if(selectedSuffixOut)
    {
        *selectedSuffixOut = ExtractFirstSuffixFromFilter(selectedFilter);
    }
    return result;
}

Qt::ConnectionType blockingGUIThreadConnection()
{
    if(QThread::currentThread() != qApp->thread())
    {
        return Qt::BlockingQueuedConnection;
    }
    else
    {
        return Qt::DirectConnection;
    }
}

bool checkPoint(const QPoint &p, const QWidget *w)
{
    QWidget *atW = QApplication::widgetAt(w->mapToGlobal(p));
    if (!atW) return false;
    return atW->topLevelWidget() == w;
}

bool isObscured(QWidget *w)
{
    return !(checkPoint(QPoint(0, 0), w)
        && checkPoint(QPoint(w->width() - 1, 0), w)
        && checkPoint(QPoint(0, w->height() - 1), w)
        && checkPoint(QPoint(w->width() - 1, w->height() - 1), w)
        && checkPoint(QPoint(w->width() / 2, w->height() / 2), w));
}

void openDebugLogfile()
{
    const boost::filesystem::path pathDebug = LogInstance().m_file_path;

    /* Open debug.log with the associated application */
    if (boost::filesystem::exists(pathDebug))
        QDesktopServices::openUrl(QUrl::fromLocalFile(boostPathToQString(pathDebug)));
}

void SubstituteFonts(const QString& language)
{
#if defined(Q_OS_MAC)
// Background:
// OSX's default font changed in 10.9 and Qt is unable to find it with its
// usual fallback methods when building against the 10.7 sdk or lower.
// The 10.8 SDK added a function to let it find the correct fallback font.
// If this fallback is not properly loaded, some characters may fail to
// render correctly.
//
// The same thing happened with 10.10. .Helvetica Neue DeskInterface is now default.
//
// Solution: If building with the 10.7 SDK or lower and the user's platform
// is 10.9 or higher at runtime, substitute the correct font. This needs to
// happen before the QApplication is created.
#if defined(MAC_OS_X_VERSION_MAX_ALLOWED) && MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_8
    if (floor(NSAppKitVersionNumber) > NSAppKitVersionNumber10_8)
    {
        if (floor(NSAppKitVersionNumber) <= NSAppKitVersionNumber10_9)
            /* On a 10.9 - 10.9.x system */
            QFont::insertSubstitution(".Lucida Grande UI", "Lucida Grande");
        else
        {
            /* 10.10 or later system */
            if (language == "zh_CN" || language == "zh_TW" || language == "zh_HK") // traditional or simplified Chinese
              QFont::insertSubstitution(".Helvetica Neue DeskInterface", "Heiti SC");
            else if (language == "ja") // Japanesee
              QFont::insertSubstitution(".Helvetica Neue DeskInterface", "Songti SC");
            else
              QFont::insertSubstitution(".Helvetica Neue DeskInterface", "Lucida Grande");
        }
    }
#endif
#endif
}

ToolTipToRichTextFilter::ToolTipToRichTextFilter(int _size_threshold, QObject *parent) :
    QObject(parent),
    size_threshold(_size_threshold)
{

}

bool ToolTipToRichTextFilter::eventFilter(QObject *obj, QEvent *evt)
{
    if(evt->type() == QEvent::ToolTipChange)
    {
        QWidget *widget = static_cast<QWidget*>(obj);
        QString tooltip = widget->toolTip();
        if(tooltip.size() > size_threshold && !tooltip.startsWith("<qt") && !Qt::mightBeRichText(tooltip))
        {
            // Envelop with <qt></qt> to make sure Qt detects this as rich text
            // Escape the current message as HTML and replace \n by <br>
            tooltip = "<qt>" + HtmlEscape(tooltip, true) + "</qt>";
            widget->setToolTip(tooltip);
            return true;
        }
    }
    return QObject::eventFilter(obj, evt);
}

#ifdef WIN32
boost::filesystem::path static StartupShortcutPath()
{
    std::string chain = ChainNameFromCommandLine();
    if (chain == CBaseChainParams::MAIN)
        return GetSpecialFolderPath(CSIDL_STARTUP) / "Firo.lnk";
    if (chain == CBaseChainParams::TESTNET) // Remove this special case when CBaseChainParams::TESTNET = "testnet4"
        return GetSpecialFolderPath(CSIDL_STARTUP) / "Firo (testnet).lnk";
    return GetSpecialFolderPath(CSIDL_STARTUP) / strprintf("Firo (%s).lnk", chain);
}

bool GetStartOnSystemStartup()
{
    // check for Bitcoin*.lnk
    return boost::filesystem::exists(StartupShortcutPath());
}

bool SetStartOnSystemStartup(bool fAutoStart)
{
    // If the shortcut exists already, remove it for updating
    boost::filesystem::remove(StartupShortcutPath());

    if (fAutoStart)
    {
        CoInitialize(NULL);

        // Get a pointer to the IShellLink interface.
        IShellLink* psl = NULL;
        HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL,
            CLSCTX_INPROC_SERVER, IID_IShellLink,
            reinterpret_cast<void**>(&psl));

        if (SUCCEEDED(hres))
        {
            // Get the current executable path
            TCHAR pszExePath[MAX_PATH];
            GetModuleFileName(NULL, pszExePath, sizeof(pszExePath));

            // Start client minimized
            QString strArgs = "-min";
            // Set -testnet /-regtest options
            strArgs += QString::fromStdString(strprintf(" -testnet=%d -regtest=%d", GetBoolArg("-testnet", false), GetBoolArg("-regtest", false)));

#ifdef UNICODE
            boost::scoped_array<TCHAR> args(new TCHAR[strArgs.length() + 1]);
            // Convert the QString to TCHAR*
            strArgs.toWCharArray(args.get());
            // Add missing '\0'-termination to string
            args[strArgs.length()] = '\0';
#endif

            // Set the path to the shortcut target
            psl->SetPath(pszExePath);
            PathRemoveFileSpec(pszExePath);
            psl->SetWorkingDirectory(pszExePath);
            psl->SetShowCmd(SW_SHOWMINNOACTIVE);
#ifndef UNICODE
            psl->SetArguments(strArgs.toStdString().c_str());
#else
            psl->SetArguments(args.get());
#endif

            // Query IShellLink for the IPersistFile interface for
            // saving the shortcut in persistent storage.
            IPersistFile* ppf = NULL;
            hres = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf));
            if (SUCCEEDED(hres))
            {
                WCHAR pwsz[MAX_PATH];
                // Ensure that the string is ANSI.
                MultiByteToWideChar(CP_ACP, 0, StartupShortcutPath().string().c_str(), -1, pwsz, MAX_PATH);
                // Save the link by calling IPersistFile::Save.
                hres = ppf->Save(pwsz, TRUE);
                ppf->Release();
                psl->Release();
                CoUninitialize();
                return true;
            }
            psl->Release();
        }
        CoUninitialize();
        return false;
    }
    return true;
}
#elif defined(Q_OS_LINUX)

// Follow the Desktop Application Autostart Spec:
// http://standards.freedesktop.org/autostart-spec/autostart-spec-latest.html

boost::filesystem::path static GetAutostartDir()
{
    namespace fs = boost::filesystem;

    char* pszConfigHome = getenv("XDG_CONFIG_HOME");
    if (pszConfigHome) return fs::path(pszConfigHome) / "autostart";
    char* pszHome = getenv("HOME");
    if (pszHome) return fs::path(pszHome) / ".config" / "autostart";
    return fs::path();
}

boost::filesystem::path static GetAutostartFilePath()
{
    std::string chain = ChainNameFromCommandLine();
    if (chain == CBaseChainParams::MAIN)
        return GetAutostartDir() / "firo.desktop";
    return GetAutostartDir() / strprintf("firo-%s.lnk", chain);
}

bool GetStartOnSystemStartup()
{
    boost::filesystem::ifstream optionFile(GetAutostartFilePath());
    if (!optionFile.good())
        return false;
    // Scan through file for "Hidden=true":
    std::string line;
    while (!optionFile.eof())
    {
        getline(optionFile, line);
        if (line.find("Hidden") != std::string::npos &&
            line.find("true") != std::string::npos)
            return false;
    }
    optionFile.close();

    return true;
}

bool SetStartOnSystemStartup(bool fAutoStart)
{
    if (!fAutoStart)
        boost::filesystem::remove(GetAutostartFilePath());
    else
    {
        char pszExePath[MAX_PATH+1];
        memset(pszExePath, 0, sizeof(pszExePath));
        if (readlink("/proc/self/exe", pszExePath, sizeof(pszExePath)-1) == -1)
            return false;

        boost::filesystem::create_directories(GetAutostartDir());

        boost::filesystem::ofstream optionFile(GetAutostartFilePath(), std::ios_base::out|std::ios_base::trunc);
        if (!optionFile.good())
            return false;
        std::string chain = ChainNameFromCommandLine();
        // Write a firo.desktop file to the autostart directory:
        optionFile << "[Desktop Entry]\n";
        optionFile << "Type=Application\n";
        if (chain == CBaseChainParams::MAIN)
            optionFile << "Name=Firo\n";
        else
            optionFile << strprintf("Name=Firo (%s)\n", chain);
        optionFile << "Exec=" << pszExePath << strprintf(" -min -testnet=%d -regtest=%d\n", GetBoolArg("-testnet", false), GetBoolArg("-regtest", false));
        optionFile << "Terminal=false\n";
        optionFile << "Hidden=false\n";
        optionFile.close();
    }
    return true;
}


#elif defined(Q_OS_MAC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
// based on: https://github.com/Mozketo/LaunchAtLoginController/blob/master/LaunchAtLoginController.m

#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

LSSharedFileListItemRef findStartupItemInList(LSSharedFileListRef list, CFURLRef findUrl);
LSSharedFileListItemRef findStartupItemInList(LSSharedFileListRef list, CFURLRef findUrl)
{
    // loop through the list of startup items and try to find the Firo app
    CFArrayRef listSnapshot = LSSharedFileListCopySnapshot(list, NULL);
    for(int i = 0; i < CFArrayGetCount(listSnapshot); i++) {
        LSSharedFileListItemRef item = (LSSharedFileListItemRef)CFArrayGetValueAtIndex(listSnapshot, i);
        UInt32 resolutionFlags = kLSSharedFileListNoUserInteraction | kLSSharedFileListDoNotMountVolumes;
        CFURLRef currentItemURL = NULL;

#if defined(MAC_OS_X_VERSION_MAX_ALLOWED) && MAC_OS_X_VERSION_MAX_ALLOWED >= 10100
    if(&LSSharedFileListItemCopyResolvedURL)
        currentItemURL = LSSharedFileListItemCopyResolvedURL(item, resolutionFlags, NULL);
#if defined(MAC_OS_X_VERSION_MIN_REQUIRED) && MAC_OS_X_VERSION_MIN_REQUIRED < 10100
    else
        LSSharedFileListItemResolve(item, resolutionFlags, &currentItemURL, NULL);
#endif
#else
    LSSharedFileListItemResolve(item, resolutionFlags, &currentItemURL, NULL);
#endif

        if(currentItemURL && CFEqual(currentItemURL, findUrl)) {
            // found
            CFRelease(currentItemURL);
            return item;
        }
        if(currentItemURL) {
            CFRelease(currentItemURL);
        }
    }
    return NULL;
}

bool GetStartOnSystemStartup()
{
    CFURLRef bitcoinAppUrl = CFBundleCopyBundleURL(CFBundleGetMainBundle());
    LSSharedFileListRef loginItems = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
    LSSharedFileListItemRef foundItem = findStartupItemInList(loginItems, bitcoinAppUrl);
    return !!foundItem; // return boolified object
}

bool SetStartOnSystemStartup(bool fAutoStart)
{
    CFURLRef bitcoinAppUrl = CFBundleCopyBundleURL(CFBundleGetMainBundle());
    LSSharedFileListRef loginItems = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
    LSSharedFileListItemRef foundItem = findStartupItemInList(loginItems, bitcoinAppUrl);

    if(fAutoStart && !foundItem) {
        // add Firo app to startup item list
        LSSharedFileListInsertItemURL(loginItems, kLSSharedFileListItemBeforeFirst, NULL, NULL, bitcoinAppUrl, NULL, NULL);
    }
    else if(!fAutoStart && foundItem) {
        // remove item
        LSSharedFileListItemRemove(loginItems, foundItem);
    }
    return true;
}
#pragma GCC diagnostic pop
#else

bool GetStartOnSystemStartup() { return false; }
bool SetStartOnSystemStartup(bool fAutoStart) { return false; }

#endif

void setClipboard(const QString& str)
{
    QApplication::clipboard()->setText(str, QClipboard::Clipboard);
    QApplication::clipboard()->setText(str, QClipboard::Selection);
}

#if BOOST_FILESYSTEM_VERSION >= 3
boost::filesystem::path qstringToBoostPath(const QString &path)
{
    return boost::filesystem::path(path.toStdString(), utf8);
}

QString boostPathToQString(const boost::filesystem::path &path)
{
    return QString::fromStdString(path.string(utf8));
}
#else
#warning Conversion between boost path and QString can use invalid character encoding with boost_filesystem v2 and older
boost::filesystem::path qstringToBoostPath(const QString &path)
{
    return boost::filesystem::path(path.toStdString());
}

QString boostPathToQString(const boost::filesystem::path &path)
{
    return QString::fromStdString(path.string());
}
#endif

QString formatDurationStr(int secs)
{
    QStringList strList;
    int days = secs / 86400;
    int hours = (secs % 86400) / 3600;
    int mins = (secs % 3600) / 60;
    int seconds = secs % 60;

    if (days)
        strList.append(QString(QObject::tr("%1 d")).arg(days));
    if (hours)
        strList.append(QString(QObject::tr("%1 h")).arg(hours));
    if (mins)
        strList.append(QString(QObject::tr("%1 m")).arg(mins));
    if (seconds || (!days && !hours && !mins))
        strList.append(QString(QObject::tr("%1 s")).arg(seconds));

    return strList.join(" ");
}

QString formatServicesStr(quint64 mask)
{
    QStringList strList;

    // Just scan the last 8 bits for now.
    for (int i = 0; i < 8; i++) {
        uint64_t check = 1 << i;
        if (mask & check)
        {
            switch (check)
            {
            case NODE_NETWORK:
                strList.append("NETWORK");
                break;
            case NODE_GETUTXO:
                strList.append("GETUTXO");
                break;
            case NODE_BLOOM:
                strList.append("BLOOM");
                break;
            case NODE_WITNESS:
                strList.append("WITNESS");
                break;
            case NODE_XTHIN:
                strList.append("XTHIN");
                break;
            default:
                strList.append(QString("%1[%2]").arg("UNKNOWN").arg(check));
            }
        }
    }

    if (strList.size())
        return strList.join(" & ");
    else
        return QObject::tr("None");
}

QString formatPingTime(double dPingTime)
{
    return (dPingTime == static_cast<double>(std::numeric_limits<int64_t>::max())/1e6 || dPingTime == 0) ? QObject::tr("N/A") : QString(QObject::tr("%1 ms")).arg(QString::number((int)(dPingTime * 1000), 10));
}

QString formatTimeOffset(int64_t nTimeOffset)
{
  return QString(QObject::tr("%1 s")).arg(QString::number((int)nTimeOffset, 10));
}

QString formatNiceTimeOffset(qint64 secs)
{
    // Represent time from last generated block in human readable text
    QString timeBehindText;
    const int HOUR_IN_SECONDS = 60*60;
    const int DAY_IN_SECONDS = 24*60*60;
    const int WEEK_IN_SECONDS = 7*24*60*60;
    const int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
    if(secs < 60)
    {
        timeBehindText = QObject::tr("%n second(s)","",secs);
    }
    else if(secs < 2*HOUR_IN_SECONDS)
    {
        timeBehindText = QObject::tr("%n minute(s)","",secs/60);
    }
    else if(secs < 2*DAY_IN_SECONDS)
    {
        timeBehindText = QObject::tr("%n hour(s)","",secs/HOUR_IN_SECONDS);
    }
    else if(secs < 2*WEEK_IN_SECONDS)
    {
        timeBehindText = QObject::tr("%n day(s)","",secs/DAY_IN_SECONDS);
    }
    else if(secs < YEAR_IN_SECONDS)
    {
        timeBehindText = QObject::tr("%n week(s)","",secs/WEEK_IN_SECONDS);
    }
    else
    {
        qint64 years = secs / YEAR_IN_SECONDS;
        qint64 remainder = secs % YEAR_IN_SECONDS;
        timeBehindText = QObject::tr("%1 and %2").arg(QObject::tr("%n year(s)", "", years)).arg(QObject::tr("%n week(s)","", remainder/WEEK_IN_SECONDS));
    }
    return timeBehindText;
}

void ClickableLabel::mouseReleaseEvent(QMouseEvent *event)
{
    Q_EMIT clicked(event->pos());
}
    
void ClickableProgressBar::mouseReleaseEvent(QMouseEvent *event)
{
    Q_EMIT clicked(event->pos());
}


void TextElideStyledItemDelegate::initStyleOption(QStyleOptionViewItem *option, const QModelIndex &index) const
{
    QStyledItemDelegate::initStyleOption(option, index);
    option->textElideMode = Qt::ElideMiddle;
}

static QString darkModeOverrideCss()
{
    return QStringLiteral(R"(
        QDialog, QMainWindow, QMenuBar, QStatusBar, RPCConsole, QWidget#RPCConsole { background-color: #110C12; color: #F5EFF3; }
        QWidget { color: #F5EFF3; }
        QFrame { background-color: transparent; }
        QToolBar { background-color: #1C151B; }
        QLabel { background-color: transparent; color: #F5EFF3; }
        QGroupBox { background-color: #1C151B; color: #F5EFF3; border-color: #362A34; }
        QGroupBox::title { background-color: #110C12; color: #F5EFF3; }
        QTabWidget::pane { background-color: #1C151B; border: 1px solid #362A34; }
        QTabBar { background-color: #110C12; }
        QTabBar::tab {
            background-color: #1C151B; color: #B4A8B2; border: 1px solid #362A34;
            border-bottom: none; padding: 6px 12px;
        }
        QTabBar::tab:selected { background-color: #A3223F; color: #FFFFFF; }
        QTabBar::tab:hover:!selected { background-color: #241B22; color: #F5EFF3; }
        QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QAbstractSpinBox {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
            selection-background-color: #DE3358;
        }
        QSpinBox::up-button, QSpinBox::down-button,
        QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
            background-color: transparent; border: none; width: 18px;
        }
        QAbstractSpinBox QLineEdit {
            background-color: transparent; border: none;
        }
        QComboBox {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
        }
        QComboBox QAbstractItemView {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
            selection-background-color: #DE3358; selection-color: #FFFFFF;
        }
        QComboBox QListView {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
        }
        QComboBox::item {
            color: #F5EFF3;
        }
        QComboBox::item:alternate {
            background-color: #1C151B; color: #F5EFF3;
        }
        QComboBox::item:selected {
            background-color: #DE3358; color: #FFFFFF;
        }
        QMenu {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
        }
        QMenu::item { color: #F5EFF3; }
        QMenu::item:selected { background-color: #362A34; color: #F5EFF3; }
        QMenu::item:disabled { color: #6E5C68; }
        QMenuBar::item:selected { background-color: #362A34; }
        QTableView, QTreeView, QListView {
            background-color: #1C151B; color: #F5EFF3;
            alternate-background-color: #241B22;
            gridline-color: #362A34;
            selection-background-color: rgba(222,51,88,0.22);
            selection-color: #F5EFF3;
        }
        QHeaderView::section { background-color: transparent; color: #8A7E88; }
        QHeaderView::section:hover { background-color: #241B22; color: #F5EFF3; }
        QScrollBar:vertical, QScrollBar:horizontal { background: #1C151B; border: none; }
        QScrollBar::handle { background: #362A34; border-radius: 4px; }
        QScrollBar::handle:hover { background: #4A3A45; }
        QScrollBar::add-line, QScrollBar::sub-line { background: none; border: none; }
        QToolTip {
            background-color: #241B22; color: #F5EFF3; border: 1px solid #362A34;
        }
        QMessageBox { background-color: #1C151B; }
        QTabWidget::pane { background-color: #1C151B; border-color: #362A34; }
        QCheckBox, QRadioButton { color: #F5EFF3; background-color: transparent; }
        QWidget#RPCConsole QPushButton#promptIcon,
        QWidget#RPCConsole QPushButton#fontSmallerButton,
        QWidget#RPCConsole QPushButton#fontBiggerButton,
        QWidget#RPCConsole QPushButton#clearButton {
            background-color: #241B22; color: #F5EFF3;
        }
        QWidget#RPCConsole QLineEdit#lineEdit {
            background-color: #1C151B; color: #F5EFF3; border: 1px solid #362A34;
        }
    )");
}

void loadTheme()
{
    AssertLockNotHeld(cs_css);
    LOCK(cs_css);

    static QString lightStylesheet;
    static QString darkStylesheet;
    static bool loaded = false;

    if (!loaded) {
        QString fileName = stylesheetDirectory + "/" + firoTheme;
        QFile qFile(fileName);
        if (!qFile.open(QFile::ReadOnly)) {
            throw std::runtime_error(strprintf("%s: Failed to open file: %s", __func__, fileName.toStdString()));
        }

        lightStylesheet = QLatin1String(qFile.readAll());
        darkStylesheet = lightStylesheet + darkModeOverrideCss();
        loaded = true;
    }

    qApp->setStyleSheet(isDarkMode() ? darkStylesheet : lightStylesheet);
}

int TextWidth(const QFontMetrics& fm, const QString& text)
{
    return fm.horizontalAdvance(text);
}

QDateTime StartOfDay(const QDate& date)
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 14, 0))
    return date.startOfDay();
#else
    return QDateTime(date);
#endif
}

bool HasPixmap(const QLabel* label)
{
#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
    return !label->pixmap(Qt::ReturnByValue).isNull();
#else
    return label->pixmap() != nullptr;
#endif
}

QImage GetImage(const QLabel* label)
{
    if (!HasPixmap(label)) {
        return QImage();
    }

#if (QT_VERSION >= QT_VERSION_CHECK(5, 15, 0))
    return label->pixmap(Qt::ReturnByValue).toImage();
#else
    return label->pixmap()->toImage();
#endif
}

} // namespace GUIUtil
