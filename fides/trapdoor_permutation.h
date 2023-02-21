//
// Created by Xu Peng on 2019/8/23.
//

#ifndef FIDES_TRAPDOOR_PERMUTATION_H
#define FIDES_TRAPDOOR_PERMUTATION_H

#include <gmp.h>

struct TdpPK
{
    TdpPK();
    ~TdpPK();
    mpz_t n;
    mpz_t e;
};

struct TdpSK
{
    TdpSK();
    ~TdpSK();
    mpz_t p;
    mpz_t q;
    mpz_t d;
    mpz_t f;
};

class TrapdoorPermutation
{
public:
    TrapdoorPermutation() = default;
    ~TrapdoorPermutation() = default;
    int generate_key_pair(TdpPK *pk, TdpSK *sk);
    int permutate_private(const TdpSK *sk, const TdpPK *pk, const unsigned char *in, unsigned int times, unsigned char *out);
    int permutate_public(const TdpPK *pk, const unsigned char *in, unsigned char *out);

};


#endif //FIDES_TRAPDOOR_PERMUTATION_H
