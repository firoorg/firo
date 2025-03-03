//
// Created by Gevorg Voskanyan
//

#include <QMessageBox>

#include "spatsburndialog.h"
#include "ui_spatsburndialog.h"

spats::supply_amount_t convert_to_supply_amount( double value, unsigned precision );

SpatsBurnDialog::SpatsBurnDialog( const PlatformStyle *platform_style, spats::asset_type_t asset_type, std::string_view asset_symbol, spats::supply_amount_t max_allowed_burn_amount, QWidget *parent )
   : QDialog( parent )
   , ui_( new Ui::SpatsBurnDialog )
   , max_allowed_burn_amount_( max_allowed_burn_amount )
{
   ui_->setupUi( this );

   ui_->burnAmountSpinBox->setDecimals( max_allowed_burn_amount.precision() );
   ui_->burnAmountSpinBox->setValue( 0.0 );                     // Default value
   ui_->burnAmountSpinBox->setMinimum( 0.0 );                   // No negative values
   ui_->burnAmountSpinBox->setSingleStep( 1.0 / max_allowed_burn_amount.decimal_factor() );   // Step controlled by precision
   ui_->burnAmountSpinBox->setMaximum( max_allowed_burn_amount.as_double() );

   setWindowTitle( QString( "Burn an Amount of Asset Type %1 (%2)" ).arg( utils::to_underlying( asset_type ) ).arg( QString::fromStdString( std::string( asset_symbol ) ) ) );

   ui_->errorLabel->setVisible( false );

   // Button connections
   connect( ui_->okButton, &QPushButton::clicked, this, &SpatsBurnDialog::onSave );
   connect( ui_->cancelButton, &QPushButton::clicked, this, &QDialog::reject );

   // Apply the PlatformStyle if needed
   if ( platform_style ) {
      // Apply styles, e.g., button/icon customization if needed
   }
}

SpatsBurnDialog::~SpatsBurnDialog() {}

void SpatsBurnDialog::onSave()
{
   try {
      validateInputs();

      // When inputs are valid
      burn_amount_ = convert_to_supply_amount( ui_->burnAmountSpinBox->value(), max_allowed_burn_amount_.precision() );

      accept(); // Close the dialog with acceptance
   }
   catch ( const std::invalid_argument &e ) {
      ui_->errorLabel->setText( e.what() );
      ui_->errorLabel->setVisible( true );
   }
}

void SpatsBurnDialog::validateInputs() const
{
   // Validate that a positive burn amount is entered
   if ( ui_->burnAmountSpinBox->value() <= 0. )
      throw std::invalid_argument( "Amount to burn must be greater than 0." );
   // and that it is not greater than the max allowed
   if ( burn_amount_ > max_allowed_burn_amount_ )
       throw std::invalid_argument( "Amount to burn exceeds the maximum allowed." );
}