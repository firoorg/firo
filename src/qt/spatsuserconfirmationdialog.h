//
// Created by Gevorg Voskanyan
//

#ifndef FIRO_QT_SPATS_USER_CONFIRMATION_DIALOG_H_INCLUDED
#define FIRO_QT_SPATS_USER_CONFIRMATION_DIALOG_H_INCLUDED

#include <boost/format.hpp>

#include "../spats/actions.hpp"
#include "../spats/user_confirmation.hpp"

#include "sendconfirmationdialog.h"

class SpatsUserConfirmationDialog : public SendConfirmationDialog {
   // Q_OBJECT

public:
   SpatsUserConfirmationDialog( const QString &title, const QString &text, QWidget *parent = nullptr )
      : SendConfirmationDialog( title, text, 3, parent )
   {}
};

namespace detail {

// internal helper function template for MakeSpatsUserConfirmationCallback()
void append_burn_amount_if_any( QString &text, const spats::concepts::Action auto &action )
{
   if ( const auto burn_amount = spats::get_associated_burn_amount( action ) ) {
      // generate bold burn amount string
      const auto tr = []( const auto &s ) { return SpatsUserConfirmationDialog::tr( s ); };
      QString amount = QString::fromStdString( "<b>" + burn_amount->first.to_string() + " " + burn_amount->second.get() + "</b> " ) + tr( "to be BURNED with this" );
      text.append( "<br />" );
      text.append( "<br />" );
      text.append( amount );
      text.append( "<br />" );
   }
}

}   // namespace detail

class WalletModel;

inline auto MakeSpatsUserConfirmationCallback( const WalletModel &wallet_model, QWidget *parent = nullptr )
{
   // internal helper function declarations
   void append_standard_fee( QString & text, CAmount standard_fee, const WalletModel &wallet_model, std::int64_t transaction_size );
   void adjust_dialog_size( SpatsUserConfirmationDialog & dlg, const QString &text );

   return [ parent, &wallet_model ]< class Action >( const Action &action, CAmount standard_fee, std::int64_t transaction_size ) {
      const auto tr = []( const auto &s ) { return SpatsUserConfirmationDialog::tr( s ); };
      const QString title = tr( "Confirm %1" ).arg( QString::fromStdString( Action::name() ) );
      QString text = tr( "Are you sure you want to perform %1 ?" ).arg( QString::fromStdString( action.summary() ) );
      detail::append_burn_amount_if_any( text, action );
      append_standard_fee( text, standard_fee, wallet_model, transaction_size );
      SpatsUserConfirmationDialog dlg( title, text, parent );
      adjust_dialog_size( dlg, text );
      dlg.exec();
      return dlg.result() == QMessageBox::Yes;
   };
}

#endif   // FIRO_QT_SPATS_USER_CONFIRMATION_DIALOG_H_INCLUDED
