//
// Created by Gevorg Voskanyan
//

#ifndef MYOWNSPATS_H_INCLUDED
#define MYOWNSPATS_H_INCLUDED

#include <QWidget>
#include <QResizeEvent>

#include "../spats/manager.hpp"

#include "platformstyle.h"

namespace Ui {
class MyOwnSpats;
}

class ClientModel;
class WalletModel;
struct NewSparkAssetCreationContext;

/** "My Own Spats" Manager page widget */
class MyOwnSpats : public QWidget, public spats::UpdatesObserver {
   Q_OBJECT

public:
   explicit MyOwnSpats( const PlatformStyle *platform_style, QWidget *parent = 0 );
   ~MyOwnSpats() override;

   // Set the client model for this page
   void setClientModel( ClientModel *client_model );

   // Set the wallet model for this page
   void setWalletModel( WalletModel *wallet_model );
   void adjustTextSize( int width, int height );

protected:
   void resizeEvent( QResizeEvent * ) override;

private Q_SLOTS:
   void onCreateButtonClicked();
   void onUnregisterButtonClicked();
   void handleDisplayMyOwnSpatsSignal() { display_my_own_spats(); }
   void updateButtonStates();

private:
   const PlatformStyle *platform_style_;
   const std::unique_ptr< Ui::MyOwnSpats > ui_;
   ClientModel *client_model_{};   // TODO consider if needed at all?
   WalletModel *wallet_model_{};
   std::map< spats::universal_asset_id_t, spats::SparkAsset > my_own_assets_map_;

Q_SIGNALS:
   void displayMyOwnSpatsSignal();

private:
   void process_registry_changed() override { Q_EMIT displayMyOwnSpatsSignal(); }

   void display_my_own_spats();

   NewSparkAssetCreationContext make_new_asset_creation_context() const;

   std::optional< int > get_the_selected_row() const;
};

#endif   // MYOWNSPATS_H_INCLUDED
