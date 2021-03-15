#include "batchproof_container.h"
#include "liblelantus/sigmaextended_verifier.h"
#include "sigma/sigmaplus_verifier.h"
#include "sigma.h"
#include "lelantus.h"

std::unique_ptr<BatchProofContainer> BatchProofContainer::instance;

BatchProofContainer* BatchProofContainer::get_instance() {
    if (instance) {
        return instance.get();
    } else {
        instance.reset(new BatchProofContainer());
        return instance.get();
    }
}

void BatchProofContainer::init() {
    tempSigmaProofs.clear();
    tempLelantusSigmaProofs.clear();
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        for (const auto& itr : tempSigmaProofs) {
            sigmaProofs[itr.first].insert(sigmaProofs[itr.first].begin(), itr.second.begin(), itr.second.end());
        }

        for (const auto& itr : tempLelantusSigmaProofs) {
            lelantusSigmaProofs[itr.first].insert(lelantusSigmaProofs[itr.first].begin(), itr.second.begin(), itr.second.end());
        }
    } else {
        batch_sigma();
        batch_lelantus();
    }
    fCollectProofs = false;
}

void BatchProofContainer::add(sigma::CoinSpend* spend,
                              bool fPadding,
                              int group_id,
                              size_t setSize,
                              bool fStartSigmaBlacklist) {
    std::pair<sigma::CoinDenomination,  std::pair<int, bool>> denominationAndId = std::make_pair(
            spend->getDenomination(), std::make_pair(group_id, fStartSigmaBlacklist));
    tempSigmaProofs[denominationAndId].push_back(SigmaProofData(spend->getProof(), spend->getCoinSerialNumber(), fPadding, setSize));
}

void BatchProofContainer::add(lelantus::JoinSplit* joinSplit,
                              const std::map<uint32_t, size_t>& setSizes,
                              const Scalar& challenge,
                              bool fStartLelantusBlacklist) {
    const std::vector<lelantus::SigmaExtendedProof>& sigma_proofs = joinSplit->getLelantusProof().sigma_proofs;
    const std::vector<Scalar>& serials = joinSplit->getCoinSerialNumbers();
    const std::vector<uint32_t>& groupIds = joinSplit->getCoinGroupIds();

    for (size_t i = 0; i < sigma_proofs.size(); i++) {
        int coinGroupId = groupIds[i] % (CENT / 1000);
        int64_t intDenom = (groupIds[i] - coinGroupId);
        intDenom *= 1000;

        sigma::CoinDenomination denomination;
        bool isSigma = sigma::IntegerToDenomination(intDenom, denomination) && joinSplit->isSigmaToLelantus();
        // pair(pair(set id, fAfterFixes), isSigmaToLelantus)
        std::pair<std::pair<uint32_t, bool>, bool> idAndFlag = std::make_pair(std::make_pair(groupIds[i], fStartLelantusBlacklist), isSigma);
        tempLelantusSigmaProofs[idAndFlag].push_back(LelantusSigmaProofData(sigma_proofs[i], serials[i], challenge, setSizes.at(groupIds[i])));
    }
}

void BatchProofContainer::removeSigma(const sigma::spend_info_container& spendSerials) {
    for (auto& spendSerial : spendSerials) {
        bool foundAtSigma =  false;
        for (auto& itr :sigmaProofs) {
            if (itr.first.first == spendSerial.second.denomination && itr.first.second.first == spendSerial.second.coinGroupId) {
                auto& vProofs = itr.second;
                for (auto dataItr = vProofs.begin(); dataItr != vProofs.end(); dataItr++) {
                    if (dataItr->coinSerialNumber == spendSerial.first) {
                        vProofs.erase(dataItr);
                        foundAtSigma = true;
                        break;
                    }
                }
            }
        }
        if (!foundAtSigma) {
            int64_t denom;
            sigma::DenominationToInteger(spendSerial.second.denomination, denom);
            int id = denom / 1000 + spendSerial.second.coinGroupId;
            // afterFixes bool with the pair of set id is considered separate set identifiers, so try to find in one set, if not found try also in another
            std::pair<std::pair<uint32_t, bool>, bool> key1 = std::make_pair(std::make_pair(id, false), true);
            std::pair<std::pair<uint32_t, bool>, bool> key2 = std::make_pair(std::make_pair(id, true), true);
            std::vector<LelantusSigmaProofData>* vProofs;
            if (lelantusSigmaProofs.count(key1) > 0)
                vProofs = &lelantusSigmaProofs[key1];
            else if (lelantusSigmaProofs.count(key2) > 0)
                vProofs = &lelantusSigmaProofs[key2];
            else
                continue;
            for (auto dataItr = vProofs->begin(); dataItr != vProofs->end(); dataItr++) {
                if (dataItr->serialNumber == spendSerial.first) {
                    vProofs->erase(dataItr);
                    break;
                }
            }
        }
    }
}
void BatchProofContainer::removeLelantus(std::unordered_map<Scalar, int> spentSerials) {
    for (auto& spendSerial : spentSerials) {
        // afterFixes bool with the pair of set id is considered separate set identifiers, so try to find in one set, if not found try also in another
        std::pair<std::pair<uint32_t, bool>, bool> key1 = std::make_pair(std::make_pair(spendSerial.second, false), true);
        std::pair<std::pair<uint32_t, bool>, bool> key2 = std::make_pair(std::make_pair(spendSerial.second, true), true);
        std::vector<LelantusSigmaProofData>* vProofs;
        if (lelantusSigmaProofs.count(key1) > 0)
            vProofs = &lelantusSigmaProofs[key1];
        else if (lelantusSigmaProofs.count(key2) > 0)
            vProofs = &lelantusSigmaProofs[key2];
        else
            continue;

        for (auto dataItr = vProofs->begin(); dataItr != vProofs->end(); dataItr++) {
            if (dataItr->serialNumber == spendSerial.first) {
                vProofs->erase(dataItr);
                break;
            }
        }
    }
}

void BatchProofContainer::batch_sigma() {
    for (const auto& itr : sigmaProofs) {
        std::vector<GroupElement> anonymity_set;
        sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
        sigmaState->GetAnonymitySet(
                itr.first.first,
                itr.first.second.first,
                itr.first.second.second,
                anonymity_set);

        size_t m = itr.second.size();
        std::vector<Scalar> serials;
        serials.reserve(m);
        vector<bool> fPadding;
        fPadding.reserve(m);
        std::vector<size_t> setSizes;
        setSizes.reserve(m);
        vector<sigma::SigmaPlusProof<Scalar, GroupElement>> proofs;
        proofs.reserve(m);

        for (auto& proofData : itr.second) {
            serials.emplace_back(proofData.coinSerialNumber);
            fPadding.emplace_back(proofData.fPadding);
            setSizes.emplace_back(proofData.anonymitySetSize);
            proofs.emplace_back(proofData.sigmaProof);
        }

        auto params = sigma::Params::get_default();
        sigma::SigmaPlusVerifier<Scalar, GroupElement> sigmaVerifier(params->get_g(), params->get_h(), params->get_n(), params->get_m());

        if (!sigmaVerifier.batch_verify(anonymity_set, serials, fPadding, setSizes, proofs)) {
            LogPrintf("Sigma batch verification failed.");
            throw std::invalid_argument("Sigma batch verification failed, please run Firo with -reindex -batching=0");
        }
    }
    sigmaProofs.clear();
}

void BatchProofContainer::batch_lelantus() {
    auto params = lelantus::Params::get_default();

    for (const auto& itr : lelantusSigmaProofs) {
        std::vector<GroupElement> anonymity_set;
        if (!itr.first.second) {
            lelantus::CLelantusState* state = lelantus::CLelantusState::GetState();
            std::vector<lelantus::PublicCoin> coins;
            state->GetAnonymitySet(
                    itr.first.first.first,
                    itr.first.first.second,
                    coins);
            anonymity_set.reserve(coins.size());
            for (auto& coin : coins)
                anonymity_set.emplace_back(coin.getValue());
        } else {
            int coinGroupId = itr.first.first.first % (CENT / 1000);
            int64_t intDenom = (itr.first.first.first - coinGroupId);
            intDenom *= 1000;
            sigma::CoinDenomination denomination;
            sigma::IntegerToDenomination(intDenom, denomination);

            std::vector<GroupElement> coins;
            sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
            sigmaState->GetAnonymitySet(
                    denomination,
                    coinGroupId,
                    true,
                    coins);

            anonymity_set.reserve(coins.size());
            for (auto& coin : coins)
                anonymity_set.emplace_back(coin + params->get_h1() * intDenom);
        }

        size_t m = itr.second.size();
        std::vector<Scalar> serials;
        serials.reserve(m);
        std::vector<size_t> setSizes;
        setSizes.reserve(m);
        std::vector<lelantus::SigmaExtendedProof> proofs;
        proofs.reserve(m);
        std::vector<Scalar> challenges;
        challenges.reserve(m);

        for (auto& proofData : itr.second) {
            serials.emplace_back(proofData.serialNumber);
            setSizes.emplace_back(proofData.anonymitySetSize);
            proofs.emplace_back(proofData.lelantusSigmaProof);
            challenges.emplace_back(proofData.challenge);
        }

        lelantus::SigmaExtendedVerifier sigmaVerifier(params->get_g(), params->get_sigma_h(), params->get_sigma_n(),
                                            params->get_sigma_m());

        if (!sigmaVerifier.batchverify(anonymity_set, challenges, serials, setSizes, proofs)) {
            LogPrintf("Lelantus batch verification failed.");
            throw std::invalid_argument("Lelantus batch verification failed, please run Firo with -reindex -batching=0");
        }
    }

    lelantusSigmaProofs.clear();
}


