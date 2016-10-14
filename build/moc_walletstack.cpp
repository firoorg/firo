/****************************************************************************
** Meta object code from reading C++ file 'walletstack.h'
**
** Created by: The Qt Meta Object Compiler version 63 (Qt 4.8.7)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/walletstack.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'walletstack.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.7. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_WalletStack[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      17,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      18,   13,   12,   12, 0x0a,
      44,   12,   12,   12, 0x0a,
      63,   12,   12,   12, 0x0a,
      81,   12,   12,   12, 0x0a,
     103,   12,   12,   12, 0x0a,
     126,   12,   12,   12, 0x0a,
     150,  145,   12,   12, 0x0a,
     177,   12,   12,   12, 0x2a,
     197,  145,   12,   12, 0x0a,
     225,   12,   12,   12, 0x2a,
     246,  145,   12,   12, 0x0a,
     276,   12,   12,   12, 0x2a,
     306,  299,   12,   12, 0x0a,
     326,   12,   12,   12, 0x0a,
     341,   12,   12,   12, 0x0a,
     360,   12,   12,   12, 0x0a,
     375,   12,   12,   12, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_WalletStack[] = {
    "WalletStack\0\0name\0setCurrentWallet(QString)\0"
    "gotoOverviewPage()\0gotoHistoryPage()\0"
    "gotoAddressBookPage()\0gotoReceiveCoinsPage()\0"
    "gotoZerocoinPage()\0addr\0"
    "gotoSendCoinsPage(QString)\0"
    "gotoSendCoinsPage()\0gotoSignMessageTab(QString)\0"
    "gotoSignMessageTab()\0gotoVerifyMessageTab(QString)\0"
    "gotoVerifyMessageTab()\0status\0"
    "encryptWallet(bool)\0backupWallet()\0"
    "changePassphrase()\0unlockWallet()\0"
    "setEncryptionStatus()\0"
};

void WalletStack::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        WalletStack *_t = static_cast<WalletStack *>(_o);
        switch (_id) {
        case 0: _t->setCurrentWallet((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->gotoOverviewPage(); break;
        case 2: _t->gotoHistoryPage(); break;
        case 3: _t->gotoAddressBookPage(); break;
        case 4: _t->gotoReceiveCoinsPage(); break;
        case 5: _t->gotoZerocoinPage(); break;
        case 6: _t->gotoSendCoinsPage((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 7: _t->gotoSendCoinsPage(); break;
        case 8: _t->gotoSignMessageTab((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 9: _t->gotoSignMessageTab(); break;
        case 10: _t->gotoVerifyMessageTab((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 11: _t->gotoVerifyMessageTab(); break;
        case 12: _t->encryptWallet((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 13: _t->backupWallet(); break;
        case 14: _t->changePassphrase(); break;
        case 15: _t->unlockWallet(); break;
        case 16: _t->setEncryptionStatus(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData WalletStack::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject WalletStack::staticMetaObject = {
    { &QStackedWidget::staticMetaObject, qt_meta_stringdata_WalletStack,
      qt_meta_data_WalletStack, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &WalletStack::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *WalletStack::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *WalletStack::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_WalletStack))
        return static_cast<void*>(const_cast< WalletStack*>(this));
    return QStackedWidget::qt_metacast(_clname);
}

int WalletStack::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QStackedWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 17)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 17;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
