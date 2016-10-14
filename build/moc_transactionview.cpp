/****************************************************************************
** Meta object code from reading C++ file 'transactionview.h'
**
** Created by: The Qt Meta Object Compiler version 63 (Qt 4.8.7)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/transactionview.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'transactionview.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.7. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_TransactionView[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      15,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: signature, parameters, type, tag, flags
      17,   16,   16,   16, 0x05,

 // slots: signature, parameters, type, tag, flags
      44,   16,   16,   16, 0x08,
      67,   16,   16,   16, 0x08,
      86,   16,   16,   16, 0x08,
     100,   16,   16,   16, 0x08,
     114,   16,   16,   16, 0x08,
     126,   16,   16,   16, 0x08,
     138,   16,   16,   16, 0x08,
     151,   16,   16,   16, 0x08,
     166,  162,   16,   16, 0x0a,
     182,  162,   16,   16, 0x0a,
     205,  198,   16,   16, 0x0a,
     235,  228,   16,   16, 0x0a,
     258,   16,   16,   16, 0x0a,
     274,   16,   16,   16, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_TransactionView[] = {
    "TransactionView\0\0doubleClicked(QModelIndex)\0"
    "contextualMenu(QPoint)\0dateRangeChanged()\0"
    "showDetails()\0copyAddress()\0editLabel()\0"
    "copyLabel()\0copyAmount()\0copyTxID()\0"
    "idx\0chooseDate(int)\0chooseType(int)\0"
    "prefix\0changedPrefix(QString)\0amount\0"
    "changedAmount(QString)\0exportClicked()\0"
    "focusTransaction(QModelIndex)\0"
};

void TransactionView::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        TransactionView *_t = static_cast<TransactionView *>(_o);
        switch (_id) {
        case 0: _t->doubleClicked((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        case 1: _t->contextualMenu((*reinterpret_cast< const QPoint(*)>(_a[1]))); break;
        case 2: _t->dateRangeChanged(); break;
        case 3: _t->showDetails(); break;
        case 4: _t->copyAddress(); break;
        case 5: _t->editLabel(); break;
        case 6: _t->copyLabel(); break;
        case 7: _t->copyAmount(); break;
        case 8: _t->copyTxID(); break;
        case 9: _t->chooseDate((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->chooseType((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 11: _t->changedPrefix((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 12: _t->changedAmount((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 13: _t->exportClicked(); break;
        case 14: _t->focusTransaction((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData TransactionView::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject TransactionView::staticMetaObject = {
    { &QWidget::staticMetaObject, qt_meta_stringdata_TransactionView,
      qt_meta_data_TransactionView, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &TransactionView::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *TransactionView::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *TransactionView::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_TransactionView))
        return static_cast<void*>(const_cast< TransactionView*>(this));
    return QWidget::qt_metacast(_clname);
}

int TransactionView::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 15)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 15;
    }
    return _id;
}

// SIGNAL 0
void TransactionView::doubleClicked(const QModelIndex & _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_END_MOC_NAMESPACE
