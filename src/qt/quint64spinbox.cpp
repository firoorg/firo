//
// Created by Gevorg Voskanyan
//

#include <cassert>

#include "quint64spinbox.h"

void QUInt64SpinBox::setValue( std::uint64_t val )
{
   val = std::clamp( val, min_, max_ );
   if ( value_ != val ) {
      value_ = val;
      QSpinBox::setValue( static_cast< int >( val % std::numeric_limits< int >::max() ) );   // Keeps the base UI synced
      Q_EMIT valueChanged( value_ );
   }
}

void QUInt64SpinBox::setRange( std::uint64_t min, std::uint64_t max ) noexcept
{
   assert( min <= max );
   QSpinBox::setRange( static_cast< int >( min % std::numeric_limits< int >::max() ), static_cast< int >( max % std::numeric_limits< int >::max() ) );
   setMinimum( min );
   setMaximum( max );
}

int QUInt64SpinBox::valueFromText( const QString &text ) const
{
   bool ok;
   const std::uint64_t val = text.toULongLong( &ok );   // Convert input text to uint64
   if ( !ok )
      return static_cast< int >( value_ % std::numeric_limits< int >::max() );   // Default behavior on failure
   return static_cast< int >( val % std::numeric_limits< int >::max() );
}

QSize QUInt64SpinBox::sizeHint() const
{
   // Base the size hint on the largest possible value
   const QFontMetrics metrics( font() );
   const QString max_text = QString::number( max_ );   // Maximum value as a string
   const int width = metrics.horizontalAdvance( max_text ) + 20;   // Add padding for spin buttons and margins
   return QSize( width, QSpinBox::sizeHint().height() );
}

QValidator::State QUInt64SpinBox::validate( QString &input, int & /*pos*/ ) const
{
   bool ok;
   const std::uint64_t parsed_value = input.toULongLong( &ok );

   if ( !ok )
      return QValidator::Invalid;   // Reject non-numeric input
   if ( parsed_value < min_ || parsed_value > max_ )
      return QValidator::Intermediate;   // Allow input but don't fully accept until valid

   return QValidator::Acceptable;   // Valid input
}