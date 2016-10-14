/****************************************************************************
** Meta object code from reading C++ file 'addresstablemodel.h'
**
** Created by: The Qt Meta Object Compiler version 63 (Qt 4.8.7)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../src/qt/addresstablemodel.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'addresstablemodel.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.7. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_AddressTableModel[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: signature, parameters, type, tag, flags
      27,   19,   18,   18, 0x05,

 // slots: signature, parameters, type, tag, flags
      86,   58,   18,   18, 0x0a,
     146,  124,   18,   18, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_AddressTableModel[] = {
    "AddressTableModel\0\0address\0"
    "defaultAddressChanged(QString)\0"
    "address,label,isMine,status\0"
    "updateEntry(QString,QString,bool,int)\0"
    "pubCoin,isUsed,status\0"
    "updateEntry(QString,QString,int)\0"
};

void AddressTableModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        AddressTableModel *_t = static_cast<AddressTableModel *>(_o);
        switch (_id) {
        case 0: _t->defaultAddressChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->updateEntry((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3])),(*reinterpret_cast< int(*)>(_a[4]))); break;
        case 2: _t->updateEntry((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3]))); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData AddressTableModel::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject AddressTableModel::staticMetaObject = {
    { &QAbstractTableModel::staticMetaObject, qt_meta_stringdata_AddressTableModel,
      qt_meta_data_AddressTableModel, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &AddressTableModel::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *AddressTableModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *AddressTableModel::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_AddressTableModel))
        return static_cast<void*>(const_cast< AddressTableModel*>(this));
    return QAbstractTableModel::qt_metacast(_clname);
}

int AddressTableModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QAbstractTableModel::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void AddressTableModel::defaultAddressChanged(const QString & _t1)
{
    void *_a[] = { 0, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_END_MOC_NAMESPACE
