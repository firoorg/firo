//
// Created by Gevorg Voskanyan
//

#include <QMessageBox>

#include "spatsmintdialog.h"
#include "ui_spatsmintdialog.h"

spats::supply_amount_t convert_to_supply_amount( double value, unsigned precision );

SpatsMintDialog::SpatsMintDialog( const PlatformStyle *platform_style, const spats::FungibleSparkAsset &asset, QWidget *parent )
   : QDialog( parent )
   , ui_( new Ui::SpatsMintDialog )
   , asset_( asset )
{
   ui_->setupUi( this );

   const auto total_supply = asset_.total_supply();
   ui_->newSupplySpinBox->setDecimals( asset_.precision() );   // Set precision based on asset's precision
   ui_->newSupplySpinBox->setValue( 0.0 );   // Default value
   ui_->newSupplySpinBox->setMinimum( 0.0 );   // No negative values
   ui_->newSupplySpinBox->setSingleStep( 1.0 / total_supply.decimal_factor() );   // Step controlled by precision
   ui_->newSupplySpinBox->setMaximum( ( total_supply.max_value() - total_supply ).as_double() );   // Maximum value

   // Display asset info in dialog title
   const auto &asset_symbol = asset_.naming().symbol.get();
   setWindowTitle( QString( "Mint for Asset %1 (%2)" ).arg( utils::to_underlying( asset_.asset_type() ) ).arg( QString::fromStdString( asset_symbol ) ) );

   ui_->errorLabel->setVisible( false );

   // Button connections
   connect( ui_->okButton, &QPushButton::clicked, this, &SpatsMintDialog::onSave );
   connect( ui_->cancelButton, &QPushButton::clicked, this, &QDialog::reject );

   // Apply the PlatformStyle if needed
   if ( platform_style ) {
      // Apply styles, e.g., button/icon customization if needed
   }
}

SpatsMintDialog::~SpatsMintDialog() {}

void SpatsMintDialog::onSave()
{
   try {
      validateInputs();

      // When inputs are valid
      new_supply_ = convert_to_supply_amount( ui_->newSupplySpinBox->value(), asset_.precision() );

      // Recipient can be empty, hence not applying a strict check
      recipient_ = ui_->recipientEdit->text().toStdString();

      accept();   // Close the dialog with acceptance
   }
   catch ( const std::invalid_argument &e ) {
      ui_->errorLabel->setText( e.what() );
      ui_->errorLabel->setVisible( true );
   }
}

void SpatsMintDialog::validateInputs()
{
   // Validate that a positive supply is entered
   if ( ui_->newSupplySpinBox->value() <= 0.0 )
      throw std::invalid_argument( "Supply must be greater than 0." );
}
