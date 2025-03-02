//
// Created by Gevorg Voskanyan
//

#include <QMessageBox>

#include "../spark/state.h"
#include "../spark/sparkwallet.h"
#include "../wallet/wallet.h"

#include "walletmodel.h"
#include "sparkassetdialog.h"
#include "spatsmintdialog.h"
#include "myownspats.h"
#include "ui_myownspats.h"

namespace {

enum MyOwnSpatsColumns {
   ColumnAssetType = 0,
   ColumnIdentifier,
   ColumnSymbol,
   ColumnName,
   ColumnDescription,
   ColumnTotalSupply,
   ColumnFungible,
   ColumnResupplyable,
   ColumnPrecision,
   ColumnMetadata,
   ColumnCount   // This keeps the count of total columns, always keep last!
};

}

MyOwnSpats::MyOwnSpats( const PlatformStyle *platform_style, QWidget *parent )
   : QWidget( parent )
   , platform_style_( platform_style )
   , ui_( std::make_unique< Ui::MyOwnSpats >() )
{
   ui_->setupUi( this );
   ui_->tableWidgetMyOwnSpats->setSelectionBehavior( QAbstractItemView::SelectRows );
   ui_->tableWidgetMyOwnSpats->setSelectionMode( QAbstractItemView::SingleSelection );
   connect( ui_->create_spark_asset, &QPushButton::clicked, this, &MyOwnSpats::onCreateButtonClicked );
   connect( ui_->mint_spark_asset, &QPushButton::clicked, this, &MyOwnSpats::onMintButtonClicked );
   connect( ui_->modify_spark_asset, &QPushButton::clicked, this, &MyOwnSpats::onModifyButtonClicked );
   connect( ui_->unregister_spark_asset, &QPushButton::clicked, this, &MyOwnSpats::onUnregisterButtonClicked );
   connect( this, &MyOwnSpats::displayMyOwnSpatsSignal, this, &MyOwnSpats::handleDisplayMyOwnSpatsSignal );
   connect( ui_->tableWidgetMyOwnSpats->selectionModel(), &QItemSelectionModel::selectionChanged, this, &MyOwnSpats::updateButtonStates );
   display_my_own_spats();
   updateButtonStates();
}

void MyOwnSpats::display_my_own_spats()
{
   if ( !wallet_model_ )
      return;   // Too soon to be able to display anything
   const auto &my_public_address = wallet_model_->getWallet()->sparkWallet->getSpatsWallet().my_public_address_as_admin();
   const auto my_own_assets = spark::CSparkState::GetState()->GetSpatsManager().registry().get_assets_administered_by( my_public_address );
   my_own_assets_map_.clear();
   auto &table_widget = *ui_->tableWidgetMyOwnSpats;
   table_widget.clearContents();
   table_widget.setRowCount( my_own_assets.size() );

   int row = 0;
   for ( const auto &asset : my_own_assets ) {
      const spats::SparkAssetDisplayAttributes a( asset );

      // Store the asset in a map for easy lookup later, e.g. when the user wants to modify it
      my_own_assets_map_.emplace( spats::universal_asset_id_t{ spats::asset_type_t{ a.asset_type }, spats::identifier_t{ a.identifier } }, asset );

      // Fill the table with all attributes to be displayed
      table_widget.setItem( row, ColumnAssetType, new QTableWidgetItem( QString::number( a.asset_type ) ) );
      table_widget.setItem( row, ColumnIdentifier, new QTableWidgetItem( QString::number( a.identifier ) ) );
      table_widget.setItem( row, ColumnSymbol, new QTableWidgetItem( QString::fromStdString( a.symbol ) ) );
      table_widget.setItem( row, ColumnName, new QTableWidgetItem( QString::fromStdString( a.name ) ) );
      table_widget.setItem( row, ColumnDescription, new QTableWidgetItem( QString::fromStdString( a.description ) ) );
      table_widget.setItem( row, ColumnTotalSupply, new QTableWidgetItem( QString::fromStdString( a.total_supply ) ) );
      table_widget.setItem( row, ColumnFungible, new QTableWidgetItem( a.fungible ? "Yes" : "No" ) );
      table_widget.setItem( row, ColumnResupplyable, new QTableWidgetItem( a.resupplyable ? "Yes" : "No" ) );
      table_widget.setItem( row, ColumnPrecision, new QTableWidgetItem( QString::number( a.precision ) ) );
      table_widget.setItem( row, ColumnMetadata, new QTableWidgetItem( QString::fromStdString( a.metadata ) ) );

      // Make the table items read-only to prevent user editing
      for ( int col = ColumnAssetType; col < ColumnCount; ++col )
         table_widget.item( row, col )->setFlags( table_widget.item( row, col )->flags() & ~Qt::ItemIsEditable );
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
   ui_->label_filter_2->setFont( font );   // TODO implement the filtering
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
         wallet_model_->getWallet()->CreateNewSparkAsset( *dialog.getResultAsset(), dialog.getResultDestinationPublicAddress() );   // TODO user confirm callback
   }
   catch ( const std::exception &e ) {
      QMessageBox::critical( this, tr( "Error" ), tr( "An error occurred: %1" ).arg( e.what() ) );
   }
}

void MyOwnSpats::onMintButtonClicked()
{
   assert( wallet_model_ );
   if ( const auto row = get_the_selected_row() ) {
      try {
         const bool resupplyable = ui_->tableWidgetMyOwnSpats->item( *row, ColumnResupplyable )->text() == "Yes";
         if ( !resupplyable )
            throw std::domain_error( "Cannot mint for a non-resupplyable asset!" );
         const spats::asset_type_t asset_type{ ui_->tableWidgetMyOwnSpats->item( *row, ColumnAssetType )->text().toULongLong() };
         assert( is_fungible_asset_type( asset_type ) );
         const auto &asset = my_own_assets_map_.at( spats::universal_asset_id_t{ asset_type, {} } );
         const auto &fungible_asset = std::get< spats::FungibleSparkAsset >( asset );
         assert( fungible_asset.resupplyable() );
         SpatsMintDialog dialog( platform_style_, fungible_asset, this );
         if ( dialog.exec() == QDialog::Accepted )
            wallet_model_->getWallet()->MintSparkAssetSupply( asset_type, dialog.getNewSupply(), dialog.getRecipient() );   // TODO user confirm callback
      }
      catch ( const std::exception &e ) {
         QMessageBox::critical( this, tr( "Error" ), tr( "An error occurred: %1" ).arg( e.what() ) );
      }
   }
   else
      QMessageBox::critical( this, tr( "Error" ), tr( "Please select an asset to mint for." ) );
}

void MyOwnSpats::onModifyButtonClicked()
{
   assert( wallet_model_ );
   if ( const auto row = get_the_selected_row() ) {
      try {
         const spats::asset_type_t asset_type{ ui_->tableWidgetMyOwnSpats->item( *row, ColumnAssetType )->text().toULongLong() };
         spats::identifier_t identifier{ 0 };
         if ( !is_fungible_asset_type( asset_type ) )
            identifier = spats::identifier_t{ ui_->tableWidgetMyOwnSpats->item( *row, ColumnIdentifier )->text().toULongLong() };
         const auto &existing_asset = my_own_assets_map_.at( spats::universal_asset_id_t{ asset_type, identifier } );
         SparkAssetDialog dialog( platform_style_, existing_asset, this );
         if ( dialog.exec() == QDialog::Accepted )
            wallet_model_->getWallet()->ModifySparkAsset( existing_asset, *dialog.getResultAsset() );   // TODO user confirm callback
      }
      catch ( const std::exception &e ) {
         QMessageBox::critical( this, tr( "Error" ), tr( "An error occurred: %1" ).arg( e.what() ) );
      }
   }
   else
      QMessageBox::critical( this, tr( "Error" ), tr( "Please select an asset to modify." ) );
}

void MyOwnSpats::onUnregisterButtonClicked()
{
   assert( wallet_model_ );
   if ( const auto row = get_the_selected_row() ) {
      try {
         const spats::asset_type_t asset_type{ ui_->tableWidgetMyOwnSpats->item( *row, ColumnAssetType )->text().toULongLong() };
         std::optional< spats::identifier_t > identifier;
         if ( !is_fungible_asset_type( asset_type ) ) {
            identifier = spats::identifier_t{ ui_->tableWidgetMyOwnSpats->item( *row, ColumnIdentifier )->text().toULongLong() };
            if ( any_other_nfts_within_same_line( asset_type, *identifier ) ) {
               const QMessageBox::StandardButton reply = QMessageBox::question( this,
                                                                                tr( "Unregister NFT" ),
                                                                                tr( "Would you like to unregister the whole NFT line or just this specific NFT?" ),
                                                                                QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel,
                                                                                QMessageBox::Cancel );
               switch ( reply ) {
                  case QMessageBox::Yes:   // The Whole Line
                     identifier.reset();
                     break;
                  case QMessageBox::No:   // Just This One
                     // Leave identifier as is, unregister only this specific NFT
                     break;
                  case QMessageBox::Cancel:   // Cancel
                  default:
                     return;   // Exit the function without performing unregistration
               }
            }
         }
         wallet_model_->getWallet()->UnregisterSparkAsset( asset_type, identifier );   // TODO user confirm callback
      }
      catch ( const std::exception &e ) {
         QMessageBox::critical( this, tr( "Error" ), tr( "An error occurred: %1" ).arg( e.what() ) );
      }
   }
   else
      QMessageBox::critical( this, tr( "Error" ), tr( "Please select an asset to unregister." ) );
}

void MyOwnSpats::updateButtonStates()
{
   // Enable or disable buttons based on whether an item is selected in the table
   const auto the_selected_row = get_the_selected_row();
   const bool row_selected = the_selected_row.has_value();
   for ( auto *const button : { ui_->modify_spark_asset, ui_->unregister_spark_asset } )
      button->setEnabled( row_selected );
   ui_->mint_spark_asset->setEnabled( row_selected && ui_->tableWidgetMyOwnSpats->item( *the_selected_row, ColumnResupplyable )->text() == "Yes" );
}

std::optional< int > MyOwnSpats::get_the_selected_row() const
{
   const auto selection = ui_->tableWidgetMyOwnSpats->selectionModel()->selectedRows();
   return selection.size() == 1 ? selection.front().row() : std::optional< int >{};
}

bool MyOwnSpats::any_other_nfts_within_same_line( spats::asset_type_t asset_type, spats::identifier_t identifier ) const
{
   assert( !is_fungible_asset_type( asset_type ) );
   assert( asset_type <= spats::max_allowed_asset_type_value );
   return std::ranges::any_of( my_own_assets_map_, [ & ]( const auto &kv ) { return kv.first.first == asset_type && kv.first.second != identifier; } );
}