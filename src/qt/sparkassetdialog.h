//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPARKASSETDIALOG_H_INCLUDED
#define FIRO_SPARKASSETDIALOG_H_INCLUDED

#include <memory>
#include <optional>

#include <QDialog>
#include <QLineEdit>
#include <QSpinBox>
#include <QCheckBox>
#include <QComboBox>
#include <QPushButton>
#include <QFormLayout>

#include "../spats/spark_asset.hpp"

class PlatformStyle;

namespace Ui {
class SparkAssetDialog;
}

struct NewSparkAssetCreationContext {
   std::string admin_public_address;
   spats::asset_type_underlying_type lowest_available_asset_type_for_new_fungible_asset;
   spats::asset_type_underlying_type lowest_available_asset_type_for_new_nft_line;
};

class SparkAssetDialog : public QDialog {
   Q_OBJECT

public:
   // existing SparkAsset to pre-fill the form with to modify, or the context for creating a new asset.
   using dialog_context_t = std::variant< spats::SparkAsset, NewSparkAssetCreationContext >;

   /**
    * Constructor for SparkAssetDialog
    *
    * @param platform_style Pointer to the PlatformStyle to apply custom styles.
    * @param existing_asset_or_creation_context_for_new_one existing SparkAsset to pre-fill the form with to modify, or the context for creating a new asset.
    * @param parent Parent widget, nullptr by default.
    */
   explicit SparkAssetDialog( const PlatformStyle *platform_style, dialog_context_t existing_asset_or_creation_context_for_new_one, QWidget *parent = nullptr );

   /**
    * Destructor for SparkAssetDialog
    */
   ~SparkAssetDialog();

   /**
    * Retrieve the resulting SparkAsset built by the dialog.
    * Called after the dialog is accepted successfully.
    *
    * @return The created or modified SparkAsset.
    */
   const std::optional< spats::SparkAsset > &getResultAsset() const { return result_asset_; }

   const std::string &getResultDestinationPublicAddress() const noexcept { return result_destination_public_address_; }

private Q_SLOTS:
   /**
    * Slot to handle saving the asset form values.
    * Validates the input and creates the appropriate type of SparkAsset.
    */
   void onSave();

   /**
    * Slot to handle changes in the "fungible" checkbox.
    * Toggles the visibility of fields specific to fungible or non-fungible types.
    *
    * @param state The new state of the fungibility checkbox.
    */
   void onFungibilityChanged( int state );

   void onAssetTypeChanged( int asset_type_value );

private:
   const dialog_context_t context_;
   std::unique_ptr< Ui::SparkAssetDialog > ui_;   ///< Pointer to the generated UI class.
   std::optional< spats::SparkAsset > result_asset_;   ///< The resulting asset after dialog completion (if any).
   std::string result_destination_public_address_;   ///< The resulting destination public address after dialog completion (if any).

   void set_fields( const spats::SparkAsset &existing_asset );

   void set_fields( const NewSparkAssetCreationContext &creation_context );

   const spats::public_address_t &get_admin_public_address() const;

   static spats::identifier_underlying_type get_lowest_available_identifier_for_nft_line( spats::asset_type_t a );
};

#endif   // FIRO_SPARKASSETDIALOG_H_INCLUDED