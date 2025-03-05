//
// Created by Gevorg Voskanyan
//

#include <iostream>   // TODO remove
#include <cmath>
#include <stdexcept>

#include <boost/numeric/conversion/cast.hpp>

#include "../utils/math.hpp"
#include "../spark/state.h"

#include "quint64spinbox.h"   // must come before ui_sparkassetdialog.h
#include "ui_sparkassetdialog.h"
#include "sparkassetdialog.h"

// TODO move to a common location, with a header usable by spatsmintdialog too
spats::supply_amount_t convert_to_supply_amount( double value, unsigned precision )
{
   const double scaled_value = value * utils::math::integral_power( std::uintmax_t( 10 ), precision );
   const spats::supply_amount_t a{ boost::numeric_cast< std::uint64_t >( std::round( scaled_value ) ), precision };
   // TODO remove:
   std::cout << std::setprecision( 12 ) << "value: " << value << " prec: " << precision << " scaled_value: " << scaled_value << " supply_amount: " << a
             << " supply_amount dbl: " << a.as_double() << std::endl;
   return a;
}

SparkAssetDialog::SparkAssetDialog( const PlatformStyle *platform_style, dialog_context_t existing_asset_or_creation_context_for_new_one, QWidget *parent )
   : QDialog( parent )
   , context_( std::move( existing_asset_or_creation_context_for_new_one ) )
   , ui_( new Ui::SparkAssetDialog )
{
   ui_->setupUi( this );

   ui_->assetTypeSpinBox->setMinimum( 1 );   // Set minimum asset type value
   ui_->assetTypeSpinBox->setMaximum( utils::to_underlying( spats::max_allowed_asset_type_value ) );   // Set maximum asset type value
   ui_->assetTypeSpinBox->setValue( 0 );   // Default value
   ui_->assetTypeSpinBox->setSingleStep( 2 );   // Step size for asset type adjustment, always keeping it within the same fungibility territory
   // TODO disable going further down if value <= 2

   ui_->identifierSpinBox->setMinimum( 0 );   // Set minimum identifier value
   ui_->identifierSpinBox->setMaximum( utils::to_underlying( spats::max_allowed_identifier_value ) );   // Set maximum identifier value

   ui_->totalSupplySpin->setMinimum( 0.0 );   // Minimum value

   // Set up the precisionSpinBox to control precision
   connect( ui_->precisionSpinBox, static_cast< void ( QSpinBox::* )( int ) >( &QSpinBox::valueChanged ), this, &SparkAssetDialog::onPrecisionChanged );
   ui_->precisionSpinBox->setMinimum( 0 );   // Allow 0 precision (integer values)
   ui_->precisionSpinBox->setMaximum( std::numeric_limits< std::uint64_t >::digits10 - 1 );
   ui_->precisionSpinBox->setValue( 8 );   // will trigger onPrecisionChanged(), which is what we want

   // Apply the PlatformStyle if needed
   if ( platform_style ) {
      // Example: Apply styles (if applicable to your PlatformStyle)
   }

   std::visit( [ this ]( auto &&arg ) { set_fields( arg ); }, context_ );

   // Connect UI elements to actions
   connect( ui_->fungibilityCheckBox, &QCheckBox::stateChanged, this, &SparkAssetDialog::onFungibilityChanged );
   connect( ui_->assetTypeSpinBox, &QUInt64SpinBox::valueChanged, this, &SparkAssetDialog::onAssetTypeChanged );
   connect( ui_->saveButton, &QPushButton::clicked, this, &SparkAssetDialog::onSave );
   connect( ui_->cancelButton, &QPushButton::clicked, this, &QDialog::reject );
}

SparkAssetDialog::~SparkAssetDialog() {}

void SparkAssetDialog::onSave()
{
   try {
      static_assert( std::is_same_v< decltype( ui_->assetTypeSpinBox->value() ), spats::asset_type_underlying_type > );
      const spats::asset_type_t asset_type{ ui_->assetTypeSpinBox->value() };
      spats::AssetNaming asset_naming( spats::nonempty_trimmed_string( ui_->assetNameEdit->text().toStdString() ),
                                       spats::nonempty_trimmed_uppercase_string( ui_->assetSymbolEdit->text().toStdString() ),
                                       ui_->assetDescriptionEdit->text().toStdString() );

      std::string metadata = ui_->metadataEdit->text().toStdString();
      auto admin_public_address = get_admin_public_address();

      if ( ui_->fungibilityCheckBox->isChecked() ) {   // Fungible Asset
         const double total_supply_value = ui_->totalSupplySpin->value();
         const unsigned precision = ui_->precisionSpinBox->value();

         // Convert total supply to spats::supply_amount_t
         const spats::supply_amount_t total_supply( convert_to_supply_amount( total_supply_value, precision ) );
         const bool resupplyable = ui_->resupplyableCheckBox->isChecked();

         result_asset_ =
           spats::FungibleSparkAsset( asset_type, std::move( asset_naming ), std::move( metadata ), std::move( admin_public_address ), total_supply, resupplyable );
      }
      else {   // Non-Fungible Asset
         static_assert( std::is_same_v< decltype( ui_->identifierSpinBox->value() ), spats::identifier_underlying_type > );
         const spats::identifier_t identifier{ ui_->identifierSpinBox->value() };
         result_asset_ = spats::NonfungibleSparkAsset( asset_type, identifier, std::move( asset_naming ), std::move( metadata ), std::move( admin_public_address ) );
      }

      if ( ui_->destinationPublicAddressEdit->isVisible() )
         result_destination_public_address_ = ui_->destinationPublicAddressEdit->text().toStdString();

      accept();   // Close the dialog with an accepted state
   }
   catch ( const std::exception &e ) {
      ui_->errorLabel->setText( e.what() );
      ui_->errorLabel->setVisible( true );
   }
}

void SparkAssetDialog::onFungibilityChanged( int state )
{
   if ( const auto *const context = std::get_if< NewSparkAssetCreationContext >( &context_ ) ) {
      const bool is_fungible = ( state == Qt::Checked );

      // Enable or disable fungible-related fields
      ui_->totalSupplySpin->setEnabled( is_fungible );
      ui_->resupplyableCheckBox->setEnabled( is_fungible );
      ui_->precisionSpinBox->setEnabled( is_fungible );
      ui_->precisionSpinBox->setValue( is_fungible ? 8 : 0 );   // will trigger onPrecisionChanged(), which is what we want

      // Non-Fungible-specific fields
      ui_->identifierSpinBox->setEnabled( !is_fungible );

      if ( is_fungible ) {
         ui_->assetTypeSpinBox->setValue( context->lowest_available_asset_type_for_new_fungible_asset );
      }
      else {
         ui_->assetTypeSpinBox->setValue( context->lowest_available_asset_type_for_new_nft_line );
         ui_->totalSupplySpin->setValue( 1. );
      }
      onAssetTypeChanged( ui_->assetTypeSpinBox->value() );
   }
   else
      assert( !"Not allowed to modify the fungibility of an existing asset" );
}

void SparkAssetDialog::onAssetTypeChanged( int asset_type_value )
{
   try {
      const auto asset_type = static_cast< spats::asset_type_t >( asset_type_value );
      const bool fungible = ui_->fungibilityCheckBox->isChecked();
      if ( fungible != spats::is_fungible_asset_type( asset_type ) )
         throw std::domain_error( "Invalid asset_type value specified for given fungibility of the asset" );
      if ( fungible )
         ui_->identifierSpinBox->setValue( 0 );
      else
         ui_->identifierSpinBox->setValue( get_lowest_available_identifier_for_nft_line( asset_type ) );
   }
   catch ( const std::exception &e ) {
      ui_->errorLabel->setText( e.what() );
      ui_->errorLabel->setVisible( true );
   }
}

void SparkAssetDialog::onPrecisionChanged( int precision_value )
{
   try {
      ui_->totalSupplySpin->setDecimals( precision_value );
      ui_->totalSupplySpin->setSingleStep( std::pow( 10, -precision_value ) );
      ui_->totalSupplySpin->setMaximum( spats::supply_amount_t( 0, precision_value ).max_value_without_signbit().as_double() );
   }
   catch ( const std::exception &e ) {
      ui_->errorLabel->setText( e.what() );
      ui_->errorLabel->setVisible( true );
   }
}

void SparkAssetDialog::set_fields( const NewSparkAssetCreationContext &creation_context )
{
   ui_->fungibilityCheckBox->setChecked( true );
   ui_->assetTypeSpinBox->setValue( creation_context.lowest_available_asset_type_for_new_fungible_asset );
   ui_->identifierSpinBox->setValue( 0 );
   ui_->assetNameEdit->clear();
   ui_->assetSymbolEdit->clear();
   ui_->assetDescriptionEdit->clear();
   ui_->metadataEdit->clear();
   ui_->totalSupplySpin->setValue( 0.0 );
   ui_->precisionSpinBox->setValue( 8 );
   ui_->resupplyableCheckBox->setChecked( false );
   ui_->errorLabel->setVisible( false );

   onFungibilityChanged( Qt::Checked );
}

void SparkAssetDialog::set_fields( const spats::SparkAsset &existing_asset )
{
   const auto &base = spats::get_base( existing_asset );

   ui_->assetTypeSpinBox->setValue( utils::to_underlying( base.asset_type() ) );
   ui_->assetNameEdit->setText( QString::fromStdString( base.naming().name.get() ) );
   ui_->assetSymbolEdit->setText( QString::fromStdString( base.naming().symbol.get() ) );
   ui_->assetDescriptionEdit->setText( QString::fromStdString( base.naming().description ) );
   ui_->metadataEdit->setText( QString::fromStdString( base.metadata() ) );

   std::visit( utils::overloaded{ [ & ]( const spats::FungibleSparkAsset &fungible ) {
                                    ui_->fungibilityCheckBox->setChecked( true );
                                    ui_->totalSupplySpin->setDecimals( fungible.precision() );
                                    ui_->totalSupplySpin->setValue( fungible.total_supply().as_double() );
                                    ui_->precisionSpinBox->setValue( fungible.precision() );
                                    ui_->resupplyableCheckBox->setChecked( fungible.resupplyable() );
                                 },
                                  [ & ]( const spats::NonfungibleSparkAsset &nft ) {
                                     ui_->fungibilityCheckBox->setChecked( false );
                                     ui_->identifierSpinBox->setValue( utils::to_underlying( nft.identifier() ) );
                                     ui_->totalSupplySpin->setDecimals( 0 );
                                     ui_->totalSupplySpin->setValue( 1. );
                                     ui_->precisionSpinBox->setValue( 0 );
                                     ui_->resupplyableCheckBox->setChecked( false );
                                  } },
               existing_asset );

   ui_->fungibilityCheckBox->setEnabled( false );
   ui_->assetTypeSpinBox->setEnabled( false );
   ui_->identifierSpinBox->setEnabled( false );
   ui_->totalSupplySpin->setEnabled( false );
   ui_->precisionSpinBox->setEnabled( false );
   ui_->resupplyableCheckBox->setEnabled( false );
   ui_->labelDestinationPublicAddress->hide();
   ui_->destinationPublicAddressEdit->hide();
}

const spats::public_address_t &SparkAssetDialog::get_admin_public_address() const
{
   return std::visit( utils::overloaded{ []( const NewSparkAssetCreationContext &context ) -> const spats::public_address_t & { return context.admin_public_address; },
                                         []( const spats::SparkAsset &asset ) -> const spats::public_address_t & { return get_base( asset ).admin_public_address(); } },
                      context_ );
}

spats::identifier_underlying_type SparkAssetDialog::get_lowest_available_identifier_for_nft_line( spats::asset_type_t a )
{
   const auto i = spark::CSparkState::GetState()->GetSpatsManager().registry().get_lowest_available_identifier_for_nft_line( a );
   if ( !i ) [[unlikely]]
      throw std::domain_error( "No available identifiers left in the NFT line, it is full!" );
   return utils::to_underlying( *i );
}
