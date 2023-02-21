//
// Created by Xu Peng on 2019/8/20.
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <list>
#include <iostream>
#include <algorithm>
#include "dianadel.h"

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
}

using std::vector;
using std::cout;
using std::endl;
using std::sort;
using std::list;
using std::string;

int DianaDelClient::Setup()
{
    FILE *f_rand = fopen("/dev/urandom", "rb");

    fread(key_se, sizeof(char), 16, f_rand);
    fclose(f_rand);

    diana_clnt.Setup();
    diana_clnt_del.Setup();
    return 1;
}

int DianaDelClient::Add(const std::string &keyword, const std::string &ind, unsigned char *label, unsigned char *enc_id,
                        unsigned char *F_K_w_ind, unsigned char *IV, unsigned char *Enc_K_counter)
{
    char w_ind[512];
    unsigned char Kw[32], bytes_to_enc_id[64], iv[16];
    unsigned int counter;
    AES_KEY aes_key;

    //ciphertexts of diana
    this->diana_clnt.update(keyword, label, counter, bytes_to_enc_id, Kw);
    for (unsigned long i = 0; i < ind.size(); i++)
        enc_id[i] = bytes_to_enc_id[i] ^ (const unsigned char) ind.c_str()[i];

    _prf_F1(Kw, keyword, ind, F_K_w_ind);

    sprintf(w_ind, "%u", counter);
    RAND_bytes(IV, 16);
    memcpy(iv, IV, 16);
    AES_set_encrypt_key(key_se, 128, &aes_key);
    AES_cbc_encrypt((unsigned char *) w_ind, Enc_K_counter, strlen(w_ind) + 1, &aes_key, iv, AES_ENCRYPT);

    return 1;
}

int DianaDelClient::Delete(const std::string &keyword, const std::string &ind, unsigned char *label,
                           unsigned char *F_K_w_ind)
{
    unsigned char Kw[32], buf1[64], bytes_to_enc_id[64];
    unsigned int counter;

    //ciphertexts of diana
    this->diana_clnt_del.update(keyword, label, counter, bytes_to_enc_id, Kw);
    this->diana_clnt.get_kw_and_kw1(keyword, Kw, Kw + 16);
    _prf_F1(Kw, keyword, ind, F_K_w_ind);

    for (int i = 0; i < 32; i++)
        F_K_w_ind[i] = F_K_w_ind[i] ^ bytes_to_enc_id[i];

    return 1;
}

int DianaDelClient::trapdoor_for_diana_clnt_del(const std::string &keyword, ConstrainedKey *trpd, unsigned char *kw1)
{
    this->diana_clnt_del.trapdoor(keyword, *trpd, kw1);
    return 1;
}

int DianaDelClient::trapdoor_for_diana_clnt(const std::string &keyword, std::vector<std::string> &enc_counters_to_del,
                                            std::vector<ConstrainedKey *> &range_keys, unsigned char *kw1)
{
    vector<unsigned int> counter_to_del;
    list<CipherRange> counter_range;
    CipherRange _t;
    unsigned char _kw[32], _kw1[32];
    char number_str[32];
    unsigned char iv[16];
    int counter;
    AES_KEY aes_key;
    ConstrainedPRF c_prf;

    AES_set_decrypt_key(key_se, 128, &aes_key);
    for (const auto &a:enc_counters_to_del)
    {
        memcpy(iv, a.c_str(), 16);
        AES_cbc_encrypt((unsigned char *) a.c_str() + 16, (unsigned char *) number_str, 16, &aes_key, iv, AES_DECRYPT);
        sscanf(number_str, "%u", &counter);
        counter_to_del.emplace_back(counter);
    }

    sort(counter_to_del.begin(), counter_to_del.end());
    _t.start = 0;
    _t.end = diana_clnt.get_keyword_counter(keyword);
    counter_range.emplace_back(_t);
    _split_counter_range(counter_to_del, counter_range);
    this->diana_clnt.get_kw_and_kw1(keyword, _kw, _kw1);

    for (const auto &a:counter_range)
    {
        auto _k = new ConstrainedKey();
        c_prf.Constrain(_kw, a.start, a.end, *_k);
        range_keys.emplace_back(_k);
    }

    memcpy(kw1, _kw1, 16);
    return 1;
}

int DianaDelClient::_split_counter_range(const std::vector<unsigned int> &counter_to_del, std::list<CipherRange> &range)
{
    for (const unsigned int &_c:counter_to_del)
    {
        for (auto it = range.begin(); it != range.end(); it++)
        {
            if ((it->start <= _c) && (it->end >= _c))
            {
                if (it->start == it->end)
                {
                    range.erase(it);
                    break;
                }
                if (it->start == _c)
                {
                    it->start = it->start + 1;
                    break;
                }
                if (it->end == _c)
                {
                    it->end = it->end - 1;
                    break;
                }
                CipherRange _t;

                _t.start = _c + 1;
                _t.end = it->end;

                it->end = _c - 1;
                range.emplace_back(_t);
                break;
            }
        }
    }
    return 1;
}

int
DianaDelClient::_prf_F1(const unsigned char *kw, const std::string &keyword, const std::string &ind, unsigned char *out)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned int out_len;
    unsigned char buf[48];

    memcpy(buf, kw, 16);
    SHA256(kw, 16, buf + 16);

    HMAC_Init_ex(ctx, buf, 48, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) ind.c_str(), ind.size());
    HMAC_Final(ctx, out, &out_len);
    HMAC_CTX_free(ctx);

    return 1;
}

void DianaDelClient::dump_data(const std::string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    fwrite(this->key_se, sizeof(char), 16, f_out);
    this->diana_clnt.dump_data(f_out);
    this->diana_clnt_del.dump_data(f_out);

    fclose(f_out);
}

void DianaDelClient::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    fread(this->key_se, sizeof(char), 16, f_in);
    this->diana_clnt.load_data(f_in);
    this->diana_clnt_del.load_data(f_in);

    fclose(f_in);
}

int DianaDelServer::Setup()
{
    this->diana_srv.Setup();
    this->diana_srv_del.Setup();
    this->enc_counter.clear();

    return 1;
}

int
DianaDelServer::Add(unsigned char *label, unsigned char *enc_id, unsigned char *F_k_w_ind, unsigned char *IV,
                    unsigned char *Enc_K_counter)
{
    this->diana_srv.Save(label, enc_id, 64);
    string _label;
    string _value;
    unsigned char buf[32];

    _label.assign((char *) F_k_w_ind, 32);
    memcpy(buf, IV, 16);
    memcpy(buf + 16, Enc_K_counter, 16);
    _value.assign((char *) buf, 32);
    this->enc_counter[_label] = _value;

    return 1;
}

int DianaDelServer::Delete(unsigned char *label, unsigned char *enc_F_K_w_ind)
{
    this->diana_srv_del.Save(label, enc_F_K_w_ind, 32);

    return 1;
}

int
DianaDelServer::SearchStage1(ConstrainedKey *trpd, unsigned char *kw1, std::vector<std::string> &enc_counters_to_del)
{
    vector<DianaData *> search_ret;

    search_ret.reserve(300000);

    this->diana_srv_del.Search(*trpd, kw1, search_ret);
    for (auto &a:search_ret)
    {
        string _s;
        _s.assign((char *) a->ct, 32);
        if (this->enc_counter.find(_s) != this->enc_counter.end())
            enc_counters_to_del.emplace_back(this->enc_counter[_s]);
    }

    for (auto &a:search_ret)
        delete a;

    return 1;
}

int DianaDelServer::SearchStage2(const std::vector<ConstrainedKey *> &range_keys, unsigned char *kw1,
                                 std::vector<std::string> &id_ret)
{
    vector<DianaData *> search_ret;
    search_ret.reserve(300000);

    for (auto &a:range_keys)
    {
        this->diana_srv.SearchRange(*a, kw1, search_ret);
    }

    for (auto &a:search_ret)
    {
        id_ret.emplace_back(string((char *) (a->ct)));
        delete a;
    }

    return 1;
}

void DianaDelServer::dump_data(const std::string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    unsigned long len_counter = this->enc_counter.size();
    unsigned long len_str;

    fwrite(&len_counter, sizeof(unsigned long), 1, f_out);

    for (auto &itr:this->enc_counter)
    {
        len_str = itr.first.size();
        fwrite(&len_str, sizeof(len_str), 1, f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        len_str = itr.second.size();
        fwrite(&len_str, sizeof(len_str), 1, f_out);
        fwrite(itr.second.c_str(), sizeof(char), len_str, f_out);
    }

    this->diana_srv.dump_data(f_out);
    this->diana_srv_del.dump_data(f_out);

    fclose(f_out);
}

void DianaDelServer::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    unsigned long len_counter, len_str;
    char buf1[500];

    this->enc_counter.clear();

    fread(&len_counter, sizeof(len_counter), 1, f_in);

    for (unsigned long i = 0; i < len_counter; i++)
    {
        string l, v;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        l.assign(buf1, len_str);

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        v.assign(buf1, len_str);

        this->enc_counter[l] = v;
    }

    this->diana_srv.load_data(f_in);
    this->diana_srv_del.load_data(f_in);

    fclose(f_in);
}
