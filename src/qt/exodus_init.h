#ifndef EXODUS_QT_INIT_H
#define EXODUS_QT_INIT_H

namespace Exodus
{
    //! Shows an user dialog with general warnings and potential risks
    bool AskUserToAcknowledgeRisks();

    //! Setup and initialization related to Exodus Qt
    bool Initialize();
}

#endif // Exodus_QT_INIT_H
