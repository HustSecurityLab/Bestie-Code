//
// Created by Xu Peng on 2019/8/14.
//


#include <cstring>
#include <vector>
#include <iostream>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/aes.h>
}

#include "constrained_prf.h"

using std::vector;
using std::cout;
using std::endl;

ConstrainedKey::~ConstrainedKey()
{
    for (auto k:this->permitted_keys)
        delete k;
}

size_t ConstrainedKey::size()
{
    size_t ret;

    ret = sizeof(int);
    ret += (16 + sizeof(int)) * permitted_keys.size();

    return ret;
}

int ConstrainedKey::hash(unsigned char *out)
{
    unsigned char buf1[64], buf2[32];
    if (this->current_permitted == 0)
        return 0;

    SHA256(this->permitted_keys[0]->key_data, 16, buf1);

    for (unsigned long i = 1; i < this->permitted_keys.size(); i++)
    {
        SHA256(this->permitted_keys[i]->key_data, 16, buf1 + 32);
        SHA256(buf1, 64, buf2);
        memcpy(buf1, buf2, 32);
    }

    memcpy(out, buf1, 32);
    return 1;
}

int ConstrainedKey::write_to_file(FILE *f_out)
{
    unsigned long number_of_keys = this->permitted_keys.size();

    fwrite(&(this->max_permitted), sizeof(int), 1, f_out);
    fwrite(&(this->current_permitted), sizeof(int), 1, f_out);
    fwrite(&(this->start), sizeof(unsigned int), 1, f_out);
    fwrite(&(this->end), sizeof(unsigned int), 1, f_out);
    fwrite(&number_of_keys, sizeof(size_t), 1, f_out);
    for (unsigned long i = 0; i < number_of_keys; i++)
    {
        ConstrainedKeyData *key_data = this->permitted_keys[i];
        fwrite(&(key_data->path), sizeof(unsigned int), 1, f_out);
        fwrite(&(key_data->level), sizeof(int), 1, f_out);
        fwrite(key_data->key_data, sizeof(unsigned char), 16, f_out);
    }

    return 1;
}

int ConstrainedKey::read_from_file(FILE *f_in)
{
    unsigned long number_of_keys;

    for (auto k:this->permitted_keys)
        delete k;
    this->permitted_keys.clear();

    fread(&(this->max_permitted), sizeof(int), 1, f_in);
    fread(&(this->current_permitted), sizeof(int), 1, f_in);
    fread(&(this->start), sizeof(unsigned int), 1, f_in);
    fread(&(this->end), sizeof(unsigned int), 1, f_in);
    fread(&number_of_keys, sizeof(size_t), 1, f_in);
    for (unsigned long i = 0; i < number_of_keys; i++)
    {
        auto key_data = new ConstrainedKeyData();
        fread(&(key_data->path), sizeof(unsigned int), 1, f_in);
        fread(&(key_data->level), sizeof(int), 1, f_in);
        fread(key_data->key_data, sizeof(unsigned char), 16, f_in);
        this->permitted_keys.emplace_back(key_data);
    }

    return 1;
}

ConstrainedPRF::ConstrainedPRF()
{
    for (int i = 0; i < 16; i++)
    {
        if (i % 2 == 1)
        {
            _data_0[i] = 1;
            _data_1[i] = 0;
        }
        else
        {
            _data_0[i] = 0;
            _data_1[i] = 1;
        }
    }
}

int ConstrainedPRF::Eval(unsigned char *K, unsigned int per_num, unsigned char *out)
{
    return this->_Eval_from_path(K, per_num, 0, out);
}

int ConstrainedPRF::_Eval_from_path(unsigned char *key, unsigned int tag, unsigned int level, unsigned char *out_result)
{
    unsigned char iv[16];
    unsigned char tmp1[64], tmp2[64];
    unsigned int mask = 1u << 31u;
    unsigned int mask_inv = ~(1u << 31u);
    AES_KEY aes_key;

    for (unsigned int i = 0; i < level; i++)
        mask = (mask >> 1u) & mask_inv;

    memcpy(tmp1, key, 16);
    memcpy(tmp2, key, 16);

    for (unsigned int i = level; i < 32; i++)
    {
        unsigned char *data_to_enc;

        if ((mask & tag) == 0)
            data_to_enc = _data_0;
        else
            data_to_enc = _data_1;

        memset(iv, 0, 16);

        if (i % 2 == 0)
        {
            AES_set_encrypt_key(tmp1, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, tmp2, 16, &aes_key, iv, AES_ENCRYPT);
        }
        else
        {
            AES_set_encrypt_key(tmp2, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, tmp1, 16, &aes_key, iv, AES_ENCRYPT);
        }
        mask = (mask >> 1u) & mask_inv;
    }

    memcpy(out_result, tmp1, 16);

    return 1;
}

int ConstrainedPRF::Constrain(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    out.current_permitted = per_num;
    out.max_permitted = ~0u;

    for (auto k:out.permitted_keys)
        delete k;
    out.permitted_keys.clear();

    if (per_num == out.max_permitted)
    {
        auto _data = new ConstrainedKeyData();
        _data->level = 0;
        memcpy(_data->key_data, K, 16);
        out.permitted_keys.emplace_back(_data);
        return 1;
    }
    //path of 1~per_num-1
    this->_Constrain_internal_nodes(K, per_num, out);
    //path of per_num
    this->_Constrain_last_nodes(K, per_num, out);

    return 1;
}

int ConstrainedPRF::_Constrain_internal_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    unsigned int mask = 1u << 31u;
    unsigned int path_mask_all_bits = 1u << 31u;
    unsigned char buf1[64], buf2[64], iv[16];
    AES_KEY aes_key;
    //all nodes excluding per_num
    for (unsigned int i = 1; i <= 32; i++)
    {
        if ((mask & per_num) != 0)
        {
            unsigned int path_mask = 1u << 31u;
            unsigned char *data_to_enc;
            memcpy(buf1, K, 16);
            memcpy(buf2, K, 16);

            for (unsigned int j = 0; j < i - 1; j++)
            {
                if ((path_mask & per_num) == 0)
                    data_to_enc = _data_0;
                else
                    data_to_enc = _data_1;

                memset(iv, 0, 16);

                if (j % 2 == 0)
                {
                    AES_set_encrypt_key(buf1, 128, &aes_key);
                    AES_cbc_encrypt(data_to_enc, buf2, 16, &aes_key, iv, AES_ENCRYPT);
                }
                else
                {
                    AES_set_encrypt_key(buf2, 128, &aes_key);
                    AES_cbc_encrypt(data_to_enc, buf1, 16, &aes_key, iv, AES_ENCRYPT);
                }
                path_mask = (path_mask >> 1u) & (~(1u << 31u));
            }

            auto _key = new ConstrainedKeyData();
            _key->level = i;
            _key->path = path_mask_all_bits & per_num;
            _key->path = _key->path ^ mask;
            data_to_enc = _data_0;
            memset(iv, 0, 16);
            if (i % 2 == 0)
            {
                AES_set_encrypt_key(buf2, 128, &aes_key);
                AES_cbc_encrypt(data_to_enc, buf1, 16, &aes_key, iv, AES_ENCRYPT);
                memcpy(_key->key_data, buf1, 16);
            }
            else
            {
                AES_set_encrypt_key(buf1, 128, &aes_key);
                AES_cbc_encrypt(data_to_enc, buf2, 16, &aes_key, iv, AES_ENCRYPT);
                memcpy(_key->key_data, buf2, 16);
            }
            out.permitted_keys.emplace_back(_key);
        }
        mask >>= 1u;
        path_mask_all_bits = (path_mask_all_bits >> 1u) | (1u << 31u);
    }

    return 1;
}

int ConstrainedPRF::_Constrain_last_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    unsigned char buf1[64], buf2[64], iv[16];
    AES_KEY aes_key;
    unsigned int path_mask = 1u << 31u;
    unsigned char *data_to_enc;

    memcpy(buf1, K, 16);
    memcpy(buf2, K, 16);
    for (int i = 0; i < 32; i++)
    {
        if ((path_mask & per_num) == 0)
            data_to_enc = _data_0;
        else
            data_to_enc = _data_1;

        memset(iv, 0, 16);

        if (i % 2 == 0)
        {
            AES_set_encrypt_key(buf1, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, buf2, 16, &aes_key, iv, AES_ENCRYPT);
        }
        else
        {
            AES_set_encrypt_key(buf2, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, buf1, 16, &aes_key, iv, AES_ENCRYPT);
        }
        path_mask = (path_mask >> 1u) & (~(1u << 31u));
    }
    auto _data = new ConstrainedKeyData();
    _data->level = 32;
    _data->path = per_num;
    memcpy(_data->key_data, buf1, 16);
    out.permitted_keys.emplace_back(_data);
    return 1;
}

int ConstrainedPRF::Eval(ConstrainedKey &key, unsigned int counter, unsigned char *out)
{
    unsigned int prefix = 1u << 31u;
    memset(out, 0, 16);

    if (counter > key.current_permitted)
        return 0;

    for (auto k:key.permitted_keys)
    {
        prefix = 1u << 31u;
        for (unsigned int j = 1; j < k->level; j++)
            prefix = (prefix >> 1u) | (1u << 31u);
        if ((prefix & k->path) == (prefix & counter))
            return _Eval_from_path(k->key_data, counter, k->level, out);
    }

    return 1;
}

int ConstrainedPRF::Constrain(const unsigned char *K, unsigned int start, unsigned int end, ConstrainedKey &out)
{
    vector<PathData> path_ret;
    unsigned char buf1[64], buf2[64], iv[16];
    AES_KEY aes_key;
    unsigned int path_mask = 1u << 31u;
    unsigned char *data_to_enc;

    if (end < start)
        return 0;

    for (auto k:out.permitted_keys)
        delete k;
    out.permitted_keys.clear();
    out.max_permitted = ~0u;

    out.start = start;
    out.end = end;

    _Constrain_between_nodes(start, end, 0, path_ret);

    for (const auto &a:path_ret)
    {
        auto _k = new ConstrainedKeyData();
        path_mask = 1u << 31u;
        memcpy(buf1, K, 16);

        for (unsigned int i = 0; i < a.level; i++)
        {
            if ((path_mask & a.path) == 0)
                data_to_enc = _data_0;
            else
                data_to_enc = _data_1;

            memset(iv, 0, 16);

            if (i % 2 == 0)
            {
                AES_set_encrypt_key(buf1, 128, &aes_key);
                AES_cbc_encrypt(data_to_enc, buf2, 16, &aes_key, iv, AES_ENCRYPT);
            }
            else
            {
                AES_set_encrypt_key(buf2, 128, &aes_key);
                AES_cbc_encrypt(data_to_enc, buf1, 16, &aes_key, iv, AES_ENCRYPT);
            }
            path_mask = (path_mask >> 1u) & (~(1u << 31u));
        }

        _k->level = a.level;
        _k->path = a.path;
        if (a.level % 2 == 0)
            memcpy(_k->key_data, buf1, 16);
        else
            memcpy(_k->key_data, buf2, 16);

        out.permitted_keys.emplace_back(_k);
    }

    return 1;

}

int ConstrainedPRF::_Constrain_between_nodes(unsigned int start, unsigned int end, unsigned int level,
                                             vector<PathData> &out)
{
    unsigned int mask = 0u;
    unsigned int path_mask = 0u;
    unsigned int min;
    unsigned int max;
    unsigned int matched_bits_num;
    unsigned int next_path_mask;
    unsigned int left_max, right_min;

    if ((start == 0u) && (end == ~0u))
    {
        PathData _p = {0u, 0u, 0u};
        out.emplace_back(_p);
        return 1;
    }

    for (unsigned int i = 0; i < level; i++)
    {
        if (mask == 0u)
        {
            mask = 1u << 31u;
            path_mask = 1u << 31u;
        }
        {
            mask = (mask >> 1u) & (~(1u << 31u));
            path_mask = (path_mask >> 1u) | (1u << 31u);
        }
    }

    for (matched_bits_num = level; matched_bits_num < 32; matched_bits_num++)
    {
        if ((start & mask) != (end & mask))
            break;

        if (mask == 0u)
        {
            mask = 1u << 31u;
            path_mask = 1u << 31u;
        }
        {
            mask = (mask >> 1u) & (~(1u << 31u));
            path_mask = (path_mask >> 1u) | (1u << 31u);
        }
    }

    min = path_mask & start;
    max = (path_mask & end) | (~path_mask);

    if (start == end)
    {
        PathData _p = {start, matched_bits_num, path_mask};
        out.emplace_back(_p);
        return 1;
    }

    if ((start == min) && (end == max))
    {
        PathData _p = {path_mask & start, matched_bits_num, path_mask};
        out.emplace_back(_p);
        return 1;
    }

    //path_mask = (path_mask >> 1u) | (1u<<31u);
    left_max = (path_mask & start) | (~path_mask);
    right_min = path_mask & end;

    _Constrain_between_nodes(start, left_max, matched_bits_num, out);
    _Constrain_between_nodes(right_min, end, matched_bits_num, out);
    return 1;
}

int ConstrainedPRF::Eval_range(ConstrainedKey &key, unsigned int counter, unsigned char *out)
{
    unsigned int prefix = 1u << 31u;

    if ((counter < key.start) || (counter > key.end))
        return 0;

    for (const auto &k:key.permitted_keys)
    {
        prefix = 1u << 31u;
        for (unsigned int j = 1; j < k->level; j++)
            prefix = (prefix >> 1u) | (1u << 31u);
        if ((prefix & k->path) == (prefix & counter))
            return _Eval_from_path(k->key_data, counter, k->level, out);
    }
    return 1;
}

