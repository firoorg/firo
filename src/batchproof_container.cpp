#include "batchproof_container.h"
#include "liblelantus/sigmaextended_verifier.h"
#include "liblelantus/threadpool.h"
#include "liblelantus/range_verifier.h"
#include "sigma/sigmaplus_verifier.h"
#include "sigma.h"
#include "lelantus.h"
#include "ui_interface.h"

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
    tempRangeProofs.clear();
}

void BatchProofContainer::finalize() {
    if (fCollectProofs) {
        for (const auto& itr : tempSigmaProofs) {
            sigmaProofs[itr.first].insert(sigmaProofs[itr.first].begin(), itr.second.begin(), itr.second.end());
        }

        for (const auto& itr : tempLelantusSigmaProofs) {
            lelantusSigmaProofs[itr.first].insert(lelantusSigmaProofs[itr.first].begin(), itr.second.begin(), itr.second.end());
        }

        for (const auto& itr : tempRangeProofs) {
            rangeProofs[itr.first].insert(rangeProofs[itr.first].begin(), itr.second.begin(), itr.second.end());
        }
    }
    fCollectProofs = false;
}

void BatchProofContainer::verify() {
    if (!fCollectProofs) {
        batch_sigma();
        batch_lelantus();
        batch_rangeProofs();
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


void BatchProofContainer::add(lelantus::JoinSplit* joinSplit, const std::vector<lelantus::PublicCoin>& Cout) {
    tempRangeProofs[joinSplit->getVersion()].push_back(std::make_pair(joinSplit->getLelantusProof().bulletproofs, Cout));
}

void BatchProofContainer::removeSigma(const sigma::spend_info_container& spendSerials) {
    for (auto& spendSerial : spendSerials) {
        for (auto& itr :sigmaProofs) {
            if (itr.first.first == spendSerial.second.denomination && itr.first.second.first == spendSerial.second.coinGroupId) {
                auto& vProofs = itr.second;
                for (auto dataItr = vProofs.begin(); dataItr != vProofs.end(); dataItr++) {
                    if (dataItr->coinSerialNumber == spendSerial.first) {
                        vProofs.erase(dataItr);
                        break;
                    }
                }
            }
        }
    }
}
void BatchProofContainer::removeLelantus(std::unordered_map<Scalar, int> spentSerials) {
    for (auto& spendSerial : spentSerials) {

        int id = spendSerial.second;
        int coinGroupId = id % (CENT / 1000);
        int64_t intDenom = (id - coinGroupId);
        intDenom *= 1000;
        sigma::CoinDenomination denomination;
        bool isSigmaToLela = false;
        if (sigma::IntegerToDenomination(intDenom, denomination))
            isSigmaToLela = true;

        // afterFixes bool with the pair of set id is considered separate set identifiers, so try to find in one set, if not found try also in another
        std::pair<std::pair<uint32_t, bool>, bool> key1 = std::make_pair(std::make_pair(id, false), isSigmaToLela);
        std::pair<std::pair<uint32_t, bool>, bool> key2 = std::make_pair(std::make_pair(id, true), isSigmaToLela);
        std::vector<LelantusSigmaProofData>* vProofs;
        if (lelantusSigmaProofs.count(key1) > 0) {
            vProofs = &lelantusSigmaProofs[key1];
            erase(vProofs, spendSerial.first);
        }

        if (lelantusSigmaProofs.count(key2) > 0) {
            vProofs = &lelantusSigmaProofs[key2];
            erase(vProofs, spendSerial.first);
        }
    }
}

void BatchProofContainer::remove(const std::vector<lelantus::RangeProof>& rangeProofsToRemove) {
    for (auto& itrRemove : rangeProofsToRemove) {
        for (auto itrVersions = rangeProofs.begin(); itrVersions != rangeProofs.end(); ++itrVersions) {
            bool found = false;
            for (auto itr = itrVersions->second.begin(); itr != itrVersions->second.end(); ++itr) {
                if (itr->first.T_x1 == itrRemove.T_x1 && itr->first.T_x2 == itrRemove.T_x2 && itr->first.u == itrRemove.u) {
                    itrVersions->second.erase(itr);
                    found = true;
                    break;
                }
            }
            if (itrVersions->second.empty()) {
                rangeProofs.erase(itrVersions);
                itrVersions--;
            }
            if (found)
                break;
        }
    }
}

void BatchProofContainer::erase(std::vector<LelantusSigmaProofData>* vProofs, const Scalar& serial) {
    vProofs->erase(std::remove_if(vProofs->begin(),
                                  vProofs->end(),
                                  [serial](LelantusSigmaProofData& proof){return proof.serialNumber == serial;}),
                   vProofs->end());

}

void BatchProofContainer::batch_sigma() {
    if (!sigmaProofs.empty()){
        LogPrintf("Sigma batch verification started.\n");
        uiInterface.UpdateProgressBarLabel("Batch verifying Sigma...");
    }
    else
        return;

    DoNotDisturb dnd;
    std::size_t threadsMaxCount = std::min((unsigned int)sigmaProofs.size(), boost::thread::hardware_concurrency());
    std::vector<boost::future<bool>> parallelTasks;
    parallelTasks.reserve(threadsMaxCount);
    ParallelOpThreadPool<bool> threadPool(threadsMaxCount);

    auto params = sigma::Params::get_default();
    sigma::SigmaPlusVerifier<Scalar, GroupElement> sigmaVerifier(params->get_g(), params->get_h(), params->get_n(), params->get_m());

    auto itr = sigmaProofs.begin();
    for (std::size_t j = 0; j < sigmaProofs.size(); j += threadsMaxCount) {
        for (std::size_t i = j; i < j + threadsMaxCount; ++i) {
            if (i < sigmaProofs.size()) {
                std::vector<GroupElement> anonymity_set;
                sigma::CSigmaState* sigmaState = sigma::CSigmaState::GetState();
                sigmaState->GetAnonymitySet(
                        itr->first.first,
                        itr->first.second.first,
                        itr->first.second.second,
                        anonymity_set);

                size_t m = itr->second.size();
                std::vector<Scalar> serials;
                serials.reserve(m);
                std::vector<bool> fPadding;
                fPadding.reserve(m);
                std::vector<size_t> setSizes;
                setSizes.reserve(m);
                std::vector<sigma::SigmaPlusProof<Scalar, GroupElement>> proofs;
                proofs.reserve(m);

                for (auto& proofData : itr->second) {
                    serials.emplace_back(proofData.coinSerialNumber);
                    fPadding.emplace_back(proofData.fPadding);
                    setSizes.emplace_back(proofData.anonymitySetSize);
                    proofs.emplace_back(proofData.sigmaProof);
                }

                parallelTasks.emplace_back(threadPool.PostTask([=]() {
                    try {
                        if (!sigmaVerifier.batch_verify(anonymity_set, serials, fPadding, setSizes, proofs))
                            return false;
                    } catch (...) {
                        return false;
                    }
                    return true;
                }));

                ++itr;
            }
        }

        bool isFail = false;
        for (auto& th : parallelTasks) {
            if (!th.get())
                isFail = true;
        }
        if (isFail) {
            LogPrintf("Sigma batch verification failed.");
            throw std::invalid_argument(
                    "Sigma batch verification failed, please run Firo with -reindex -batching=0");
        }
        parallelTasks.clear();
    }
    if (!sigmaProofs.empty())
        LogPrintf("Sigma batch verification finished successfully.\n");
    sigmaProofs.clear();
}

void BatchProofContainer::batch_lelantus() {
    if (!lelantusSigmaProofs.empty()){
        LogPrintf("Lelantus batch verification started.\n");
        uiInterface.UpdateProgressBarLabel("Batch verifying Lelantus...");
    }
    else
        return;

    auto params = lelantus::Params::get_default();

    DoNotDisturb dnd;
    std::size_t threadsMaxCount = std::min((unsigned int)lelantusSigmaProofs.size(), boost::thread::hardware_concurrency());
    std::vector<boost::future<bool>> parallelTasks;
    parallelTasks.reserve(threadsMaxCount);
    ParallelOpThreadPool<bool> threadPool(threadsMaxCount);
    auto itr = lelantusSigmaProofs.begin();

    lelantus::SigmaExtendedVerifier sigmaVerifier(params->get_g(), params->get_sigma_h(), params->get_sigma_n(),
                                                  params->get_sigma_m());
    for (std::size_t j = 0; j < lelantusSigmaProofs.size(); j += threadsMaxCount) {
        for (std::size_t i = j; i < j + threadsMaxCount; ++i) {
            if (i < lelantusSigmaProofs.size()) {
                std::vector<GroupElement> anonymity_set;
                if (!itr->first.second) {
                    lelantus::CLelantusState* state = lelantus::CLelantusState::GetState();
                    std::vector<lelantus::PublicCoin> coins;
                    state->GetAnonymitySet(
                            itr->first.first.first,
                            itr->first.first.second,
                            coins);
                    anonymity_set.reserve(coins.size());
                    for (auto& coin : coins)
                        anonymity_set.emplace_back(coin.getValue());
                } else {
                    int coinGroupId = itr->first.first.first % (CENT / 1000);
                    int64_t intDenom = (itr->first.first.first - coinGroupId);
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

                size_t m = itr->second.size();
                std::vector<Scalar> serials;
                serials.reserve(m);
                std::vector<size_t> setSizes;
                setSizes.reserve(m);
                std::vector<lelantus::SigmaExtendedProof> proofs;
                proofs.reserve(m);
                std::vector<Scalar> challenges;
                challenges.reserve(m);

                for (auto& proofData : itr->second) {
                    serials.emplace_back(proofData.serialNumber);
                    setSizes.emplace_back(proofData.anonymitySetSize);
                    proofs.emplace_back(proofData.lelantusSigmaProof);
                    challenges.emplace_back(proofData.challenge);
                }



                parallelTasks.emplace_back(threadPool.PostTask([=]() {
                    try {
                        if (!sigmaVerifier.batchverify(anonymity_set, challenges, serials, setSizes, proofs))
                            return false;
                    } catch (...) {
                        return false;
                    }
                    return true;
                }));
                
                ++itr;
            }
        }
        bool isFail = false;
        for (auto& th : parallelTasks) {
            if (!th.get())
                isFail = true;
        }

        if (isFail) {
            LogPrintf("Lelantus batch verification failed.");
            throw std::invalid_argument("Lelantus batch verification failed, please run Firo with -reindex -batching=0");
        }

        parallelTasks.clear();
    }
    if (!lelantusSigmaProofs.empty())
        LogPrintf("Lelantus batch verification finished successfully.\n");
    lelantusSigmaProofs.clear();
}

void BatchProofContainer::batch_rangeProofs() {
    if (!rangeProofs.empty()){
        LogPrintf("RangeProof batch verification started.\n");
        uiInterface.UpdateProgressBarLabel("Batch verifying Range Proofs...");
    }

    auto params = lelantus::Params::get_default();
    for (const auto& itr : rangeProofs) {
        lelantus::RangeVerifier  rangeVerifier(params->get_h1(), params->get_h0(), params->get_g(), params->get_bulletproofs_g(), params->get_bulletproofs_h(), params->get_bulletproofs_n(), itr.first);
        std::vector<std::vector<GroupElement>> V;
        std::vector<std::vector<GroupElement>> commitments;
        size_t proofSize = itr.second.size();
        V.resize(proofSize); //size of batch
        commitments.resize(proofSize); // size of batch
        std::vector<lelantus::RangeProof> proofs;
        proofs.reserve(proofSize); // size of batch
        for (size_t i = 0; i < proofSize; ++i) {
            size_t coutSize = itr.second[i].second.size();
            std::size_t m = coutSize * 2;

            while (m & (m - 1))
                m++;
            proofs.emplace_back(itr.second[i].first);
            V[i].reserve(m); // aggregation size
            commitments[i].reserve(2 * coutSize);
            commitments[i].resize(coutSize); // prepend zero elements, to match the prover's behavior
            auto& Cout = itr.second[i].second;
            for (std::size_t j = 0; j < coutSize; ++j) {
                V[i].push_back(Cout[j].getValue());
                V[i].push_back(Cout[j].getValue() + params->get_h1_limit_range());
                commitments[i].emplace_back(Cout[j].getValue());
            }

            // Pad with zero elements
            for (std::size_t t = coutSize * 2; t < m; ++t)
                V[i].push_back(GroupElement());
        }

        if (!rangeVerifier.verify(V, commitments, proofs)) {
            LogPrintf("RangeProof batch verification failed.\n");
            throw std::invalid_argument("RangeProof batch verification failed, please run Firo with -reindex -batching=0");
        }
    }

    if (!rangeProofs.empty())
        LogPrintf("RangeProof batch verification finished successfully.\n");

    rangeProofs.clear();
}
