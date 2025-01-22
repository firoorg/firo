//
// Created by Gevorg Voskanyan
//

#include <QMessageBox>

#include "../spark/state.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"

#include "walletmodel.h"
#include "sparkassetdialog.h"
#include "myownspats.h"
#include "ui_myownspats.h"

MyOwnSpats::MyOwnSpats( const PlatformStyle *platform_style, QWidget *parent )
   : QWidget( parent )
   , platform_style_( platform_style )
   , ui_( std::make_unique< Ui::MyOwnSpats >() )
{
   ui_->setupUi( this );
   connect( ui_->create_spark_asset, &QPushButton::clicked, this, &MyOwnSpats::onCreateButtonClicked );
   connect( this, &MyOwnSpats::displayMyOwnSpatsSignal, this, &MyOwnSpats::handleDisplayMyOwnSpatsSignal );
   display_my_own_spats();
}

void MyOwnSpats::display_my_own_spats()
{
   if ( !wallet_model_ )
      return;   // Too soon to be able to display anything
   const auto &my_public_address = wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();
   const auto my_own_assets = spark::CSparkState::GetState()->GetSpatsManager().registry().get_assets_administered_by( my_public_address );
   my_own_assets_map_.clear();
   ui_->tableWidgetMyOwnSpats->clearContents();
   ui_->tableWidgetMyOwnSpats->setRowCount( my_own_assets.size() );

   int row = 0;
   for ( const auto &asset : my_own_assets ) {
      const spats::SparkAssetDisplayAttributes a( asset );

      // Store the asset in a map for easy lookup later, e.g. when the user wants to modify it
      my_own_assets_map_.emplace( spats::universal_asset_id_t{ spats::asset_type_t{ a.asset_type }, spats::identifier_t{ a.identifier } }, asset );

      QTableWidgetItem *item;

      // Fill the table with all attributes to be displayed
      ui_->tableWidgetMyOwnSpats->setItem( row, 0, new QTableWidgetItem( QString::number( a.asset_type ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 1, new QTableWidgetItem( QString::number( a.identifier ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 2, new QTableWidgetItem( QString::fromStdString( a.symbol ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 3, new QTableWidgetItem( QString::fromStdString( a.name ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 4, new QTableWidgetItem( QString::fromStdString( a.description ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 5, new QTableWidgetItem( QString::fromStdString( a.total_supply ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 6, new QTableWidgetItem( a.fungible ? "Yes" : "No" ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 7, new QTableWidgetItem( a.resupplyable ? "Yes" : "No" ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 8, new QTableWidgetItem( QString::number( a.precision ) ) );
      ui_->tableWidgetMyOwnSpats->setItem( row, 9, new QTableWidgetItem( QString::fromStdString( a.metadata ) ) );

      // Make the table items read-only to prevent user editing
      for ( int col = 0; col < 10; ++col )
         ui_->tableWidgetMyOwnSpats->item( row, col )->setFlags( ui_->tableWidgetMyOwnSpats->item( row, col )->flags() & ~Qt::ItemIsEditable );
      ++row;
   }

   ui_->countLabel->setText( QString::number( my_own_assets.size() ) );
}

MyOwnSpats::~MyOwnSpats() {}

void MyOwnSpats::setClientModel( ClientModel *model )
{
   if ( client_model_ ) {
      // Disconnect signals from old model, if any
   }
   client_model_ = model;
   if ( model ) {
      // Connect necessary signals for UI updates, if any
   }
}

void MyOwnSpats::setWalletModel( WalletModel *model )
{
   if ( wallet_model_ ) {
      // Disconnect signals from old model, if any
   }
   wallet_model_ = model;
   if ( model ) {
      // Connect necessary signals for UI updates
      spark::CSparkState::GetState()->GetSpatsManager().set_updates_observer( this );
      display_my_own_spats();
   }
}

void MyOwnSpats::resizeEvent( QResizeEvent *event )
{
   QWidget::resizeEvent( event );
   adjustTextSize( width(), height() );
}

void MyOwnSpats::adjustTextSize( int width, int height )
{
   const double font_size_scaling_factor = 70.0;
   const int base_font_size = std::min( width, height ) / font_size_scaling_factor;
   const int font_size = std::min( 15, std::max( 12, base_font_size ) );
   QFont font = this->font();
   font.setPointSize( font_size );

   // Set font size for all labels
   ui_->label_filter_2->setFont( font );
   ui_->label_count_2->setFont( font );
   ui_->countLabel->setFont( font );
   ui_->tableWidgetMyOwnSpats->setFont( font );
   ui_->tableWidgetMyOwnSpats->horizontalHeader()->setFont( font );
   ui_->tableWidgetMyOwnSpats->verticalHeader()->setFont( font );
}

NewSparkAssetCreationContext MyOwnSpats::make_new_asset_creation_context() const
{
   const auto &registry = spark::CSparkState::GetState()->GetSpatsManager().registry();
   const auto lowest_available_asset_type_for_new_fungible_asset = registry.get_lowest_available_asset_type_for_new_fungible_asset();
   if ( !lowest_available_asset_type_for_new_fungible_asset ) [[unlikely]]
      throw std::domain_error( "No available fungible asset type values left, all possible values are taken!" );
   const auto lowest_available_asset_type_for_new_nft_line = registry.get_lowest_available_asset_type_for_new_nft_line();
   if ( !lowest_available_asset_type_for_new_nft_line ) [[unlikely]]
      throw std::domain_error( "No available NFT line asset type values left, all possible values are taken!" );
   return NewSparkAssetCreationContext{ wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin(),
                                        utils::to_underlying( *lowest_available_asset_type_for_new_fungible_asset ),
                                        utils::to_underlying( *lowest_available_asset_type_for_new_nft_line ) };
}

void MyOwnSpats::onCreateButtonClicked()
{
   assert( wallet_model_ );
   try {
      SparkAssetDialog dialog( platform_style_, make_new_asset_creation_context(), this );
      if ( dialog.exec() == QDialog::Accepted )
         wallet_model_->getWallet()->CreateNewSparkAsset( *dialog.getResultAsset() );   // TODO user confirm callback
   }
   catch ( const std::exception &e ) {
      QMessageBox::critical( this, tr( "Error" ), tr( "An error occurred: %1" ).arg( e.what() ) );
   }
}