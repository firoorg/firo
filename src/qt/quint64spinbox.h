//
// Created by Gevorg Voskanyan
//

#include <cstdint>
#include <limits>
#include <algorithm>

#include <QSpinBox>
#include <QString>

class QUInt64SpinBox : public QSpinBox {
   Q_OBJECT

public:
   QUInt64SpinBox( QWidget *parent = nullptr )
      : QSpinBox( parent )
   {
      updateWidth();   // Ensure the width is set initially
   }

   std::uint64_t value() const noexcept { return value_; }

   void setValue( std::uint64_t val );

   std::uint64_t minimum() const noexcept { return min_; }
   void setMinimum( std::uint64_t min ) noexcept { min_ = min; }

   std::uint64_t maximum() const noexcept { return max_; }
   void setMaximum( std::uint64_t max )
   {
      max_ = max;
      updateWidth();   // Recalculate width when max value is updated
   }

   void setRange( std::uint64_t min, std::uint64_t max ) noexcept;

   std::uint64_t singleStep() const noexcept { return step_; }
   void setSingleStep( std::uint64_t step ) noexcept { step_ = step; }

protected:
   void stepBy( int steps ) override
   {
      // Steps can be positive (increment) or negative (decrement)
      setValue( value_ + steps * step_ );   // Apply the updated value
   }

   QString textFromValue( int /*val*/ ) const override
   {
      return QString::number( value_ );   // Convert the uint64 to a string
   }

   int valueFromText( const QString &text ) const override;

   QSize sizeHint() const override;

   // Validates user input for quint64 range
   QValidator::State validate( QString &input, int &pos ) const override;

Q_SIGNALS:
   void valueChanged( std::uint64_t new_value );

private:
   void updateWidth()
   {
      // Update the minimum width based on the computed size hint
      setMinimumWidth( sizeHint().width() );
   }

   std::uint64_t value_ = 0;   // Store the actual uint64 value
   std::uint64_t min_ = 0;   // Minimum value for uint64
   std::uint64_t max_ = std::numeric_limits< std::uint64_t >::max();   // Maximum value for uint64
   std::uint64_t step_ = 1;   // Step size for increment/decrement (singleStep)
};
