//
// Created by Xu Peng on 2019/8/12.
//

#ifndef JANUSPP_PUN_ENCRYPTION_H
#define JANUSPP_PUN_ENCRYPTION_H

#include <vector>
#include "pun_prf.h"


struct PunEncryptionKey
{
    PunEncryptionKey() = default;

    explicit PunEncryptionKey(int d);

    explicit PunEncryptionKey(int d, unsigned char *data);

    PunEncryptionKey(const PunEncryptionKey &k);

    PunEncryptionKey &operator=(const PunEncryptionKey &k);

    ~PunEncryptionKey();

    int max_deletion;
    int current_deleted;

    std::vector<PuncturedKey *> key_data;
    unsigned char initial_key[16];

    size_t size();

    int hash(unsigned char *hash_out);
};

class PunEncryption
{
public:
    PunEncryption() = default;

    PunEncryptionKey *generate_key(int max_deletion);

    int puncture(PunEncryptionKey *key, PunTag &tag, PuncturedKey *psk);

    int incremental_punc(unsigned char *key, PunTag &tag, PuncturedKey *psk, unsigned char *key_next);

    int encrypt(PunEncryptionKey *key, PunTag &tag, const char *id, unsigned char *IV, unsigned char *output);

    int encrypt_with_low_storage(PunEncryptionKey *key, PunTag &tag, const char *id, unsigned char *IV,
                                 unsigned char *output);

    int decrypt(PunEncryptionKey *key, PunTag &tag, const unsigned char *IV, const unsigned char *enc_data, char *id);

private:
    PuncturablePRF _punc_prf;

};

#endif //JANUSPP_PUN_ENCRYPTION_H
