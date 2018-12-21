#include <boost/test/unit_test.hpp>

#include <libzerocoin/sigma/SigmaPrimitives.h>
#include <secp256k1/include/Scalar.h>
#include <secp256k1/include/GroupElement.h>

BOOST_AUTO_TEST_SUITE(sima_primitives_tests)

BOOST_AUTO_TEST_CASE(pedersen_commitment_test)
{
    // g*x+h*r == expected
    secp_primitives::GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
        "33986433546870000256104618635743654523665060392313886665479090285075695067131");
    secp_primitives::GroupElement h("50204771751011461524623624559944050110546921468100198079190811223951215371253",
        "71960464583475414858258501028406090652116947054627619400863446545880957517934");

    secp_primitives::Scalar x(10);
    secp_primitives::Scalar r(20);

    std::string expected;
    expected = std::string("(61851512099084226466548221129323427278009818728918965264765669380819444390860,"
    "74410384199099167977559468576631224214387698148107087854255519197692763637450)");

    secp_primitives::GroupElement c;
    c = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, x, h, r);

    BOOST_TEST(expected == c.tostring());
}

BOOST_AUTO_TEST_CASE(homomorphic_test)
{
    // commit(x1,r1)+commit(x2,r2) = commit(x1+x2,r1+r2)
    secp_primitives::GroupElement h;
    h.randomize();

    secp_primitives::GroupElement g;
    g.randomize();

    secp_primitives::Scalar x1;
    x1.randomize();
    secp_primitives::Scalar r1;
    r1.randomize();

    secp_primitives::Scalar x2;
    x2.randomize();
    secp_primitives::Scalar r2;
    r2.randomize();

    // commit(x1,r1)
    secp_primitives::GroupElement t1;
    t1 = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, x1, h, r1);

    // commit(x2,r2)
    secp_primitives::GroupElement t2;
    t2 = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, x2, h, r2);

    // commit(x1+x2,r1+r2)
    secp_primitives::GroupElement t3;
    t3 = sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, x1+x2, h, r1+r2);

    BOOST_CHECK(t1+t2 == t3);
}

BOOST_AUTO_TEST_CASE(commit2_test)
{
    // g*r+h*x == expected
    secp_primitives::GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
        "33986433546870000256104618635743654523665060392313886665479090285075695067131");
    secp_primitives::GroupElement h("50204771751011461524623624559944050110546921468100198079190811223951215371253",
        "71960464583475414858258501028406090652116947054627619400863446545880957517934");
    std::vector<secp_primitives::GroupElement> h_;
    h_.push_back(h);

    zcoin_common::GeneratorVector<secp_primitives::Scalar, secp_primitives::GroupElement> h_gens(h_);

    secp_primitives::Scalar r(10);

    std::vector<secp_primitives::Scalar> x_;
    x_.push_back(secp_primitives::Scalar(20));

    std::string expected;
    expected = std::string("(61851512099084226466548221129323427278009818728918965264765669380819444390860,"
    "74410384199099167977559468576631224214387698148107087854255519197692763637450)");

    secp_primitives::GroupElement resulted;
    sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g,h_,x_,r,resulted);

    BOOST_TEST(expected == resulted.tostring());
}

BOOST_AUTO_TEST_CASE(commit2_vs_test)
{
    // g*r+h*x == expected
    secp_primitives::GroupElement g("9216064434961179932092223867844635691966339998754536116709681652691785432045",
        "33986433546870000256104618635743654523665060392313886665479090285075695067131");
    secp_primitives::GroupElement h1("50204771751011461524623624559944050110546921468100198079190811223951215371253",
        "71960464583475414858258501028406090652116947054627619400863446545880957517934");
    secp_primitives::GroupElement h2("7143275630583997983432964947790981761478339235433352888289260750805571589245",
        "11700086115751491157288596384709446578503357013980342842588483174733971680454");
    std::vector<secp_primitives::GroupElement> h_;
    h_.push_back(h1);
    h_.push_back(h2);

    zcoin_common::GeneratorVector<secp_primitives::Scalar, secp_primitives::GroupElement> h_gens(h_);

    secp_primitives::Scalar r(10);

    std::vector<secp_primitives::Scalar> x_;
    x_.push_back(secp_primitives::Scalar(20));
    x_.push_back(secp_primitives::Scalar(30));

    std::string expected;
    expected = std::string("(70526180889965554490147039875158729645670819462806403227314362575089997039220,"
			"2222570326551458324082940637823059881421581507683863189059174257118412428198)");

    secp_primitives::GroupElement resulted;
    sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g,h_,x_,r,resulted);

    BOOST_TEST(expected == resulted.tostring());
}

BOOST_AUTO_TEST_CASE(commit2_homomorphic_test)
{
    // commit(x1,x2:r)+commit(y1,y2:q) == commit(x1+y1,x2+y2:r+q)
    secp_primitives::GroupElement h1;
    h1.randomize();
    secp_primitives::GroupElement h2;
    h2.randomize();

    std::vector<secp_primitives::GroupElement> h_;
    h_.push_back(h1);
    h_.push_back(h2);

    zcoin_common::GeneratorVector<secp_primitives::Scalar, secp_primitives::GroupElement> h_gens(h_);

    secp_primitives::GroupElement g;
    g.randomize();

    secp_primitives::Scalar x1;
    x1.randomize();
    secp_primitives::Scalar x2;
    x2.randomize();
    std::vector<secp_primitives::Scalar> x_;
    x_.push_back(x1);
    x_.push_back(x2);

    secp_primitives::Scalar r;
    r.randomize();

    secp_primitives::Scalar y1;
    y1.randomize();
    secp_primitives::Scalar y2;
    y2.randomize();
    std::vector<secp_primitives::Scalar> y_;
    y_.push_back(y1);
    y_.push_back(y2);

    secp_primitives::Scalar q;
    q.randomize();

    std::vector<secp_primitives::Scalar> xy_;
    xy_.push_back(x1+y1);
    xy_.push_back(x2+y2);

    // commit(x1,x2:r)
    secp_primitives::GroupElement t1;
    sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, h_gens, x_, r,t1);

    // commit(y1,y2:q)
    secp_primitives::GroupElement t2;
    sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, h_gens, y_, q,t2);

    // commit(x1+y1,x2+y2:r+q)
    secp_primitives::GroupElement t3;
    sigma::SigmaPrimitives<secp_primitives::Scalar,secp_primitives::GroupElement>::commit(g, h_gens, xy_, r+q,t3);

    BOOST_CHECK(t1+t2 == t3);
}

BOOST_AUTO_TEST_SUITE_END()
