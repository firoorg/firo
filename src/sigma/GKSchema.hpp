//
//  GKSchema.hpp
//  sigma
//
//  Created by David Gray on 29/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#ifndef GKSchema_hpp
#define GKSchema_hpp

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string.h>
#include <vector>
#include "crypto/common.h"
#include "utilstrencodings.h"
#include "GKNumbers.hpp"
#include "GKGroups.hpp"
#include <cassert>
#include "GKDebug.hpp"

namespace GK {

    inline size_t BIT(size_t x,size_t i) { // index using 1,2,...
        return (x >> (i-1)) & 0x1;
    }

    inline int DELTA(int x,int y) {
        return x == y ? 1 : 0;
    }

    template <class Exponent, class GroupElement>
    class Commit {
    public:

        Commit() {
        }

        Commit(const Generators<Exponent,GroupElement>& generators,const Exponent& m,const Exponent& r) : _m(m), _r(r) {
            generators.doCommit(m,r,_commit);
        }

        Commit(const Generators<Exponent,GroupElement>& generators,const Exponent& m) : _m(m) {
            _r.random();
            generators.doCommit(m,_r,_commit);
        }

        const Exponent& m() const {
            return _m;
        }

        const Exponent& r() const {
            return _r;
        }

        const GroupElement& commit() const {
            return _commit;
        }

        void set(const Generators<Exponent,GroupElement>& generators,const Exponent& m) {
            _m = m;
            _r.random();
            generators.doCommit(_m,_r,_commit) ;
        }

        void setCommit(const GroupElement& commit) {
            _commit = commit;
        }


    protected:
        Exponent        _m;
        Exponent        _r;
        GroupElement    _commit;

        friend std::ostream& operator<< ( std::ostream& os, const Commit& c ) {
            os << "(" << c._m << "," << c._r << "," << c._commit << ")";
            return os;
        }

    };

    template <class Exponent, class GroupElement>
    class CommitDataPackage {
    public:
        Commit<Exponent,GroupElement> cl;
        Commit<Exponent,GroupElement> ca;
        Commit<Exponent,GroupElement> cb;
        Commit<Exponent,GroupElement> pk;
        GroupElement cd;

        CommitDataPackage() {
        }

        friend std::ostream& operator<< ( std::ostream& os, const CommitDataPackage& c ) {
            os  << "cl: " << c.cl << std::endl
            << "ca: " << c.ca << std::endl
            << "cb: " << c.cb << std::endl
            << "pk: " << c.pk << std::endl
            << "cd: " << c.cd << std::endl;
            return os;
        }

    };

    template <class Exponent, class GroupElement>
    class CommitPackage {
    public:
        GroupElement cl;
        GroupElement ca;
        GroupElement cb;
        GroupElement cd;

        CommitPackage() {
        }

        friend bool operator == (const CommitPackage& op1,const CommitPackage& op2) {
            return  op1.cl == op2.cl &&
            op1.ca == op2.ca &&
            op1.cb == op2.cb &&
            op1.cd == op2.cd;
        }

        friend bool operator != (const CommitPackage& op1,const CommitPackage& op2) {
            return !(op1 == op2);
        }

        friend std::ostream& operator<< ( std::ostream& os, const CommitPackage& c ) {
            os  << "cl: " << c.cl << std::endl
            << "ca: " << c.ca << std::endl
            << "cb: " << c.cb << std::endl
            << "cd: " << c.cd << std::endl;
            return os;
        }

    };

    template <class Exponent, class GroupElement>
    class ResponsePackage {
    public:
        Exponent f;
        Exponent za;
        Exponent zb;

        ResponsePackage() {
        }

        friend bool operator == (const ResponsePackage& op1,const ResponsePackage& op2) {
            return  op1.f == op2.f &&
            op1.za == op2.za &&
            op1.zb == op2.zb ;
        }

        friend bool operator != (const ResponsePackage& op1,const ResponsePackage& op2) {
            return !(op1 == op2);
        }

        friend std::ostream& operator<< ( std::ostream& os, const ResponsePackage& c ) {
            os  << "f: " << c.f << std::endl
            << "za: " << c.za << std::endl
            << "zb: " << c.zb << std::endl;
            return os;
        }

    };

    template <class Exponent>
    class Coefficients {
    public:
        std::vector<Exponent> coefficients = { 1 };

        Coefficients() {
        }

        void newFactor(Exponent x,Exponent a) {
            Exponent t((int64_t)0);
            for (int i = 0; i < coefficients.size(); i++) {
                Exponent c(coefficients[i]);
                coefficients[i] = Exponent(t).add(Exponent(c).mult(a));
                t = Exponent(c).mult(x);
            }
            coefficients.push_back(t);
        }

        friend std::ostream& operator<< ( std::ostream& os, const Coefficients& c ) {
            os << " [  ";
            for (int i = 0; i < c.coefficients.size(); i++) {
                os << c.coefficients[i] << "  ";
            }
            os << "] ";
            return os;
        }

    };

    enum DateType {binary = 0, exponent, groupElement, groupVector, commitVector, responseVector };

    template <class Exponent, class GroupElement>
    class GKWriteBuffer {
    public:

        GKWriteBuffer(int size = CHUNK_SIZE){
            _data = new unsigned char[size];
            _next = _data;
            _len = size;
        }

        ~GKWriteBuffer() {
            delete _data;
        }

        void add(const std::string& data) {
            const char* raw = data.c_str();
            size_t len = strlen(raw);
            ensureSpace(len + 3);
            *_next++ = binary;
            WriteLE16(_next,uint16_t(len));
            _next += 2;
            memcpy(_next,raw,len);
            _next += len;
        }

        void add(const Exponent& data) {
            ensureSpace(data.writeMemoryRequired()+1);
            *_next++ = exponent;
            _next = data.encode(_next);
        }

        void add(const GroupElement& data) {
            ensureSpace(data.writeMemoryRequired()+1);
            *_next++ = groupElement;
            _next = data.encode(_next);
        }

        void add(const std::vector<GroupElement>& data) {
            ensureSpace(3);
            *_next++ = groupVector;
            WriteLE16(_next,uint16_t(data.size()));
            _next += 2;
            for (int i = 0; i < data.size(); i++) {
                add(data[i]);
            }
        }

        void add(const std::vector<CommitPackage<Exponent,GroupElement>>& data) {
            ensureSpace(3);
            *_next++ = commitVector;
            WriteLE16(_next,uint16_t(data.size()));
            _next += 2;
            for (int i = 0; i < data.size(); i++) {
                const CommitPackage<Exponent,GroupElement>& package = data[i];
                add(package.cl);
                add(package.ca);
                add(package.cb);
                add(package.cd);
            }
        }

        void add(const std::vector<ResponsePackage<Exponent,GroupElement>>& data) {
            ensureSpace(3);
            *_next++ = responseVector;
            WriteLE16(_next,uint16_t(data.size()));
            _next += 2;
            for (int i = 0; i < data.size(); i++) {
                const ResponsePackage<Exponent,GroupElement>& package = data[i];
                add(package.f);
                add(package.za);
                add(package.zb);
            }
        }

        const unsigned char* data(size_t& len) const  {
            len = _next-_data;
            return _data;
        }

        std::string base64EncodedData() const {
            return EncodeBase64(_data,_next-_data);
        }

        Exponent hash() const {
            Exponent x;
            x.hash(_data,_next-_data);
            return x;
        };

    private:

        unsigned char* _data;
        unsigned char* _next;
        size_t _len;

        void ensureSpace(size_t len){
            if (_len - (_next-_data) < len) {
                unsigned char* newBuffer = new unsigned char[_len + CHUNK_SIZE];
                memcpy(newBuffer,_data,_next-_data);
                _len = _len + CHUNK_SIZE;
                _next = newBuffer + (_next-_data);
                delete _data;
                _data = newBuffer;
            }
        }

        static const size_t CHUNK_SIZE = 20*1024;

    };

    template <class Exponent, class GroupElement>
    class GKReadBuffer {
    public:

        GKReadBuffer(const unsigned char* data,size_t len) {
            _data = new unsigned char[len];
            _next = _data;
            _len = len;
            memcpy(_data,data,len);
        }

        GKReadBuffer(const std::string& base64Encoding){
            std::vector<unsigned char> decoded = DecodeBase64( base64Encoding.c_str());
            _data = new unsigned char[decoded.size()];
            _next = _data;
            _len = decoded.size();
            memcpy(_data,decoded.data(),_len);
        }

        ~GKReadBuffer()  {
            delete _data;
        }

        void get(std::string& data)  {
            assert(data.empty());
            checkData(3);
            if (*_next++ != binary) {
                throw std::string("Binary data expected in GKReadBuffer object");
            }
            uint16_t len = ReadLE16(_next);
            _next += 2;
            data.append((const char*)_next,0,len);
            _next += len;
        }

        void get(Exponent& data) {
            checkData(1);
            if (*_next++ != exponent) {
                throw std::string("Exponent expected in GKReadBuffer object");
            }
            size_t len = data.readMemoryRequired(_next);
            checkData(len);
            _next = data.decode(_next);
        }

        void get(GroupElement& data) {
            checkData(1);
            if (*_next++ != groupElement) {
                throw std::string("Group element expected in GKReadBuffer object");
            }
            size_t len = data.readMemoryRequired(_next);
            checkData(len);
            _next = data.decode(_next);
        }

        void get(std::vector<GroupElement>& data)  {
            assert(data.size() == 0);
            checkData(3);
            if (*_next++ != groupVector) {
                throw std::string("Group element vector data expected in GKReadBuffer object");
            }
            uint16_t count = ReadLE16(_next);
            _next += 2;
            for (int i = 0; i < count; i++) {
                GroupElement value;
                get(value);
                data.push_back(value);
            }
        }

        void get(std::vector<CommitPackage<Exponent,GroupElement>>& data) {
            assert(data.size() == 0);
            checkData(3);
            if (*_next++ != commitVector) {
                throw std::string("Commit vector data expected in GKReadBuffer object");
            }
            uint16_t count = ReadLE16(_next);
            _next += 2;
            for (int i = 0; i < count; i++) {
                CommitPackage<Exponent,GroupElement> package;
                get(package.cl);
                get(package.ca);
                get(package.cb);
                get(package.cd);
                data.push_back(package);
            }
        }

        void get(std::vector<ResponsePackage<Exponent,GroupElement>>& data) {
            checkData(3);
            if (*_next++ != responseVector) {
                throw std::string("Response vector data expected in GKReadBuffer object");
            }
            uint16_t count = ReadLE16(_next);
            _next += 2;
            for (int i = 0; i < count; i++) {
                ResponsePackage<Exponent,GroupElement> package;
                get(package.f);
                get(package.za);
                get(package.zb);
                data.push_back(package);
            }
        }


    private:

        unsigned char* _data;
        unsigned char* _next;
        size_t _len;

        void checkData(size_t len) const {
            if ((_next - _data + len) > _len) {
                throw std::string("Insufficient data in GKReadBuffer object");
            }
        }

    };


    template <class Exponent, class GroupElement>
    CommitPackage<Exponent,GroupElement> setupComms(const CommitDataPackage<Exponent,GroupElement>& dpackage) {
        CommitPackage<Exponent,GroupElement> cpackage;
        cpackage.cl = dpackage.cl.commit();
        cpackage.ca = dpackage.ca.commit();
        cpackage.cb = dpackage.cb.commit();
        cpackage.cd = dpackage.cd;
        return cpackage;
    }



    template <class Exponent, class GroupElement>
    void OneOutOfNCommit(const Generators<Exponent,GroupElement>& generators,
                         const std::vector<GroupElement>& commits,
                         size_t index,
                         Exponent rr,
                         std::vector<CommitDataPackage<Exponent,GroupElement>>& dpackages,
                         std::vector<CommitPackage<Exponent,GroupElement>>& cpackages) {

        size_t N = commits.size();
        size_t n = GK::numberOfBits(N);
        assert(dpackages.size() == 0);
        assert(cpackages.size() == 0);

        {
            for (size_t j = 1; j <= n; j++) {
                CommitDataPackage<Exponent,GroupElement> package;
                package.cl.set(generators,BIT(index,j));
                package.ca.set(generators,Exponent((int64_t)0).random());
                package.cb.set(generators,Exponent(package.ca.m()).mult(BIT(index,j)));
                package.pk.set(generators,Exponent((int64_t)0));
                dpackages.push_back(package);
            }

            std::vector<Coefficients<Exponent>> polynomials(N);
            for (size_t i = 0; i < N; i++) {
                Coefficients<Exponent>& coefficients = polynomials[i];
                for (size_t j = 1; j <= n; j++) {
                    Exponent a(dpackages[j-1].ca.m());
                    if (BIT(i,j) == 0) {
                        if (BIT(index,j) == 0) {
                            coefficients.newFactor(Exponent((int64_t)1),Exponent((int64_t)0).sub(a));
                        } else {
                            coefficients.newFactor(Exponent((int64_t)0),Exponent((int64_t)0).sub(a));
                        }
                    } else {
                        if (BIT(index,j) == 0) {
                            coefficients.newFactor(Exponent((int64_t)0),a);
                        } else {
                            coefficients.newFactor(Exponent((int64_t)1),a);
                        }
                    }
                }
            }
            for (size_t j = 1; j <= n; j++) {
                CommitDataPackage<Exponent,GroupElement>& package = dpackages[j-1];
                int k = j - 1;
                package.cd = package.pk.commit();

                for (size_t i = 0; i < N; i++) {
                    Coefficients<Exponent> coefficients = polynomials[i];
                    package.cd.mult(GroupElement(commits[i]).expm(coefficients.coefficients[k]));
                }
            }
        }
        {
            for (size_t j = 1; j <= n; j++) {
                cpackages.push_back(setupComms(dpackages[j-1]));
            }
        }
    }

    template <class Exponent, class GroupElement>
    void OneOutOfNResponse(const std::vector<GroupElement>& commits,
                           const std::vector<CommitDataPackage<Exponent,GroupElement>>& dpackages,
                           Exponent challenge,
                           Exponent rr,
                           std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
                           Exponent& zd) {

        size_t N = commits.size();
        size_t n = GK::numberOfBits(N);
        assert(rpackages.size() == 0);

        {
            for (size_t j = 1; j <= n; j++) {
                ResponsePackage<Exponent,GroupElement> package;
                package.f  =  Exponent(dpackages[j-1].cl.m()).mult(challenge).add(dpackages[j-1].ca.m());
                package.za =  Exponent(dpackages[j-1].cl.r()).mult(challenge).add(dpackages[j-1].ca.r());
                package.zb =  Exponent(dpackages[j-1].cl.r()).mult(Exponent(challenge).sub(package.f)).add(dpackages[j-1].cb.r());
                rpackages.push_back(package);
            }
        }
        zd = Exponent(rr).mult(Exponent(challenge).expm(n));
        Exponent w((int64_t)0);
        for (size_t k = 0; k < n; k++) {
            Exponent term(Exponent(dpackages[k].pk.r()).mult(Exponent(challenge).expm(k)));
            w.add(term);
        }
        zd.sub(w);
    }

    template <class T>
    void ensureMembership(T element) {
        if (!element.isMember()) {
            std::cerr << "Membership test failed" << std::endl;
            std::cerr << element << std::endl;
///////            throw std::string("Membership test failed");
        }
    }

    template <class Exponent, class GroupElement>
    void OneOutOfNVerify(const Generators<Exponent,GroupElement>& generators,
                         const std::vector<GroupElement>& commits,
                         const std::vector<CommitPackage<Exponent,GroupElement>>& cpackages,
                         const std::vector<ResponsePackage<Exponent,GroupElement>>& rpackages,
                         Exponent zd,
                         Exponent challenge) {

        size_t N = (int)commits.size();
        size_t  n = GK::numberOfBits(N);
        assert(cpackages.size() == n);
        assert(rpackages.size() == n);

        for (size_t i = 1; i < cpackages.size(); i++) {
            const CommitPackage<Exponent,GroupElement>& cpackage = cpackages[i-1];
            ensureMembership(cpackage.cl);
            ensureMembership(cpackage.ca);
            ensureMembership(cpackage.cb);
            ensureMembership(cpackage.cd);
        }

        for (size_t i = 1; i < rpackages.size(); i++) {
            const ResponsePackage<Exponent,GroupElement>& rpackage = rpackages[i-1];
            ensureMembership(rpackage.f);
            ensureMembership(rpackage.za);
            ensureMembership(rpackage.zb);
        }

        for (size_t j = 1; j <= n; j++) {
            const ResponsePackage<Exponent,GroupElement>& rpackage = rpackages[j-1];
            const CommitPackage<Exponent,GroupElement>& cpackage = cpackages[j-1];
            {
                Commit<Exponent,GroupElement> commit(generators,rpackage.f,rpackage.za);
                GroupElement left(GroupElement(cpackage.cl).expm(challenge).mult(cpackage.ca));
                if (!left.equal(commit.commit())) {
                    std::ostringstream str;
                    str << "ZK test 1 failed : (" << challenge << "," << j << ")";
                    throw str.str();
                }
            }
            {
                Commit<Exponent,GroupElement> commit(generators,Exponent((int64_t)0),rpackage.zb);
                GroupElement left(GroupElement(cpackage.cl).expm(Exponent(challenge).sub(rpackage.f)).mult(cpackage.cb));
                if (!left.equal(commit.commit())) {
                    std::ostringstream str;
                    str << "ZK test 2 failed : (" << challenge << "," << j << ")";
                    throw str.str();
                }
            }
        }
        {
            GroupElement t1;
            for (size_t i = 0; i < N; i++) {

                Exponent e(1);
                for (size_t j = 1; j <= n; j++) {
                    if (BIT(i,j) == 0) {
                        e.mult(Exponent(challenge).sub(rpackages[j-1].f));
                    } else {
                        e.mult(rpackages[j-1].f);
                    }
                }
                t1.mult(GroupElement(commits[i]).expm(e));
            }

            GroupElement t2;
            for (size_t k = 0; k < n; k++) {
                // Exponent e(Exponent((int64_t)0).sub(Exponent(challenge).expm(k)));
                // GroupElement y(GroupElement(cpackages[k+1].cd).expm(e));
                Exponent e(Exponent(challenge).expm(k));
                GroupElement y(GroupElement(cpackages[k].cd).expm(e).invm());
                t2.mult(y);
            }
            //std::cout << t2 << std::endl;

            GroupElement t3;
            Exponent xk;
            xk.sub(1);
            Exponent negChallenge;
            negChallenge.sub(challenge);
            for (size_t k = 0; k < n; k++) {
                Exponent e(Exponent((int64_t)0).sub(Exponent(challenge).expm(k)));
                GroupElement y(GroupElement(cpackages[k].cd).expm(xk));
                t3.mult(y);
                xk.mult(negChallenge);
            }

            GroupElement left(GroupElement(t1).mult(t2));
            GroupElement temp(GroupElement(t1).mult(t3));
            Commit<Exponent,GroupElement> commit(generators,Exponent((int64_t)0),zd);
            if (!left.equal(commit.commit())) {
                std::ostringstream str;
                str << "ZK test 3 failed : (" << challenge << ")";
                throw str.str();
            }
        }
    }
}

#endif /* GKSchema_hpp */
