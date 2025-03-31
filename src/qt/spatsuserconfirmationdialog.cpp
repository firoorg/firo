//
// Created by Gevorg Voskanyan
//

#include <boost/cast.hpp>

#include <QSpacerItem>
#include <QGridLayout>

#include "walletmodel.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"

#include "spatsuserconfirmationdialog.h"

void append_standard_fee( QString &text, CAmount standard_fee, const WalletModel &wallet_model, std::int64_t transaction_size )
{
   if ( standard_fee > 0 ) {
      // append fee string if a fee is required (should always be the case, but checking just in case)
      const auto tr = []( const auto &s ) { return SpatsUserConfirmationDialog::tr( s ); };
      text.append( "<hr /><span style='color:#aa0000;'>" );
      text.append( BitcoinUnits::formatHtmlWithUnit( wallet_model.getOptionsModel()->getDisplayUnit(), standard_fee ) );
      text.append( "</span> " );
      text.append( tr( "added as transaction fee" ) );
      // append transaction size
      text.append( " (" + QString::number( transaction_size / 1000. ) + " kB)" );
   }
}

void adjust_dialog_size( SpatsUserConfirmationDialog &dlg, const QString &text )
{
   const QFontMetrics font_metrics( dlg.font() );
   int text_width = font_metrics.boundingRect( QRect( 0, 0, 0, 0 ), Qt::TextSingleLine, text ).width();
   if ( text_width < 1500 && text_width > 610 ) {   // these are just numbers I came up with via trial and error, worked well for me, but YMMV
      text_width -= 610;
      QSpacerItem *horizontal_spacer = new QSpacerItem( text_width, 0, QSizePolicy::Fixed, QSizePolicy::Expanding );
      dlg.setText( text );
      QGridLayout &layout = boost::polymorphic_downcast< QGridLayout & >( *dlg.layout() );
      layout.addItem( horizontal_spacer, layout.rowCount(), 0, 1, layout.columnCount() );
   }
   // TODO remove
   std::cout << "text_width: " << text_width << " dlgminwidth: " << dlg.minimumWidth() << " dlgwidth: " << dlg.width() << std::endl;
}