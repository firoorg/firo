/****************************************************************************
** Meta object code from reading C++ file 'coincontroldialog.h'
**
** Created by: The Qt Meta Object Compiler version 63 (Qt 4.8.7)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/coincontroldialog.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'coincontroldialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.7. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CoinControlDialog[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      22,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      19,   18,   18,   18, 0x08,
      36,   18,   18,   18, 0x08,
      49,   18,   18,   18, 0x08,
      61,   18,   18,   18, 0x08,
      75,   18,   18,   18, 0x08,
      97,   18,   18,   18, 0x08,
     108,   18,   18,   18, 0x08,
     121,   18,   18,   18, 0x08,
     141,   18,   18,   18, 0x08,
     159,   18,   18,   18, 0x08,
     174,   18,   18,   18, 0x08,
     194,   18,   18,   18, 0x08,
     211,   18,   18,   18, 0x08,
     231,   18,   18,   18, 0x08,
     252,   18,   18,   18, 0x08,
     270,   18,   18,   18, 0x08,
     290,   18,   18,   18, 0x08,
     312,  310,   18,   18, 0x08,
     350,   18,   18,   18, 0x08,
     376,   18,   18,   18, 0x08,
     411,   18,   18,   18, 0x08,
     436,   18,   18,   18, 0x08,

       0        // eod
};

static const char qt_meta_stringdata_CoinControlDialog[] = {
    "CoinControlDialog\0\0showMenu(QPoint)\0"
    "copyAmount()\0copyLabel()\0copyAddress()\0"
    "copyTransactionHash()\0lockCoin()\0"
    "unlockCoin()\0clipboardQuantity()\0"
    "clipboardAmount()\0clipboardFee()\0"
    "clipboardAfterFee()\0clipboardBytes()\0"
    "clipboardPriority()\0clipboardLowOutput()\0"
    "clipboardChange()\0radioTreeMode(bool)\0"
    "radioListMode(bool)\0,\0"
    "viewItemChanged(QTreeWidgetItem*,int)\0"
    "headerSectionClicked(int)\0"
    "buttonBoxClicked(QAbstractButton*)\0"
    "buttonSelectAllClicked()\0updateLabelLocked()\0"
};

void CoinControlDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CoinControlDialog *_t = static_cast<CoinControlDialog *>(_o);
        switch (_id) {
        case 0: _t->showMenu((*reinterpret_cast< const QPoint(*)>(_a[1]))); break;
        case 1: _t->copyAmount(); break;
        case 2: _t->copyLabel(); break;
        case 3: _t->copyAddress(); break;
        case 4: _t->copyTransactionHash(); break;
        case 5: _t->lockCoin(); break;
        case 6: _t->unlockCoin(); break;
        case 7: _t->clipboardQuantity(); break;
        case 8: _t->clipboardAmount(); break;
        case 9: _t->clipboardFee(); break;
        case 10: _t->clipboardAfterFee(); break;
        case 11: _t->clipboardBytes(); break;
        case 12: _t->clipboardPriority(); break;
        case 13: _t->clipboardLowOutput(); break;
        case 14: _t->clipboardChange(); break;
        case 15: _t->radioTreeMode((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 16: _t->radioListMode((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 17: _t->viewItemChanged((*reinterpret_cast< QTreeWidgetItem*(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 18: _t->headerSectionClicked((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 19: _t->buttonBoxClicked((*reinterpret_cast< QAbstractButton*(*)>(_a[1]))); break;
        case 20: _t->buttonSelectAllClicked(); break;
        case 21: _t->updateLabelLocked(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CoinControlDialog::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CoinControlDialog::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CoinControlDialog,
      qt_meta_data_CoinControlDialog, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CoinControlDialog::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CoinControlDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CoinControlDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CoinControlDialog))
        return static_cast<void*>(const_cast< CoinControlDialog*>(this));
    return QDialog::qt_metacast(_clname);
}

int CoinControlDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 22)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 22;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
