//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATSMINTDIALOG_H_INCLUDED
#define FIRO_SPATSMINTDIALOG_H_INCLUDED

#include <memory>
#include <optional>
#include <string>

#include <QDialog>
#include <QDoubleSpinBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>

#include "../spats/spark_asset.hpp"

class PlatformStyle;

namespace Ui {
class SpatsMintDialog;
}

class SpatsMintDialog : public QDialog {
   Q_OBJECT

public:
   /**
    * Constructor for SpatsMintDialog
    *
    * @param platform_style Pointer to the PlatformStyle to apply custom styles.
    * @param asset Reference to the FungibleSparkAsset for which the minting is to be done.
    * @param parent Parent widget.
    */
   explicit SpatsMintDialog( const PlatformStyle *platform_style, const spats::FungibleSparkAsset &asset, QWidget *parent = nullptr );

   /**
    * Destructor for SpatsMintDialog
    */
   ~SpatsMintDialog() override;

   /**
    * Get the entered supply value.
    *
    * @return The new supply value as a double.
    */
   spats::supply_amount_t getNewSupply() const noexcept { return new_supply_; }

   /**
    * Get the recipient address entered by the user.
    *
    * @return The recipient address as a string.
    */
   const std::string &getRecipient() const noexcept { return recipient_; }

private Q_SLOTS:
   /**
    * Slot to handle saving the minting values.
    * Ensures input is valid before accepting the dialog.
    */
   void onSave();

private:
   std::unique_ptr< Ui::SpatsMintDialog > ui_;   ///< Pointer to the generated UI class.
   const spats::FungibleSparkAsset &asset_;   ///< Reference to the asset being minted for.
   spats::supply_amount_t new_supply_;   ///< The resulting new supply value.
   std::string recipient_;   ///< The resulting recipient address after dialog completion (if any).

   void validateInputs();
};

#endif   // FIRO_SPATSMINTDIALOG_H_INCLUDED
