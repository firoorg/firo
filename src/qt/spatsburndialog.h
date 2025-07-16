//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_SPATSBURNDIALOG_H_INCLUDED
#define FIRO_SPATSBURNDIALOG_H_INCLUDED

#include <memory>
#include <QDialog>

#include "../spats/spark_asset.hpp"

class PlatformStyle;

namespace Ui {
class SpatsBurnDialog;
}

class SpatsBurnDialog : public QDialog {
   Q_OBJECT

public:
   /**
    * Constructor for SpatsBurnDialog
    *
    * @param platform_style Pointer to the PlatformStyle to apply custom styles.
    * @param asset_type The asset type an amount of which is to be burned
    * @param asset_symbol The asset symbol an amount of which is to be burned
    * @param max_allowed_burn_amount The cap for the burn amount (usually, the user's balance)
    * @param parent Parent widget.
    */
   explicit SpatsBurnDialog( const PlatformStyle *platform_style, spats::asset_type_t asset_type, std::string_view asset_symbol, spats::supply_amount_t max_allowed_burn_amount, QWidget *parent = nullptr );

   /**
    * Destructor for SpatsBurnDialog
    */
   ~SpatsBurnDialog() override;

   /**
    * Get the entered burn amount.
    */
   spats::supply_amount_t getBurnAmount() const noexcept { return burn_amount_; }

private Q_SLOTS:
   /**
    * Slot to handle saving the burn amount.
    * Ensures input is valid before accepting the dialog.
    */
   void onSave();

private:
   std::unique_ptr< Ui::SpatsBurnDialog > ui_;       ///< Pointer to the generated UI class.
   spats::supply_amount_t max_allowed_burn_amount_;  ///< User's total balance, which caps the burn amount.
   spats::supply_amount_t burn_amount_;              ///< The resulting burn amount (entered by the user).

   void validateInputs() const;
};

#endif // FIRO_SPATSBURNDIALOG_H_INCLUDED
