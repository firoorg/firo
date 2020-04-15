#ifndef ZCOIN_NOTIFYZNODEWARNING_H
#define ZCOIN_NOTIFYZNODEWARNING_H

class NotifyZnodeWarning
{
public:

    ~NotifyZnodeWarning();

    static void notify();
    static bool shouldShow();
    static bool shown;
};

#endif //ZCOIN_NOTIFYZNODEWARNING_H
