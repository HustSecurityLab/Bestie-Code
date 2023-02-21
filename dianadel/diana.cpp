//
// Created by Xu Peng on 2019/8/15.
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <iostream>
extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
}
#include "diana.h"

using std::map;
using std::string;
using std::cout;
using std::endl;

int DianaClient::Setup()
{
    FILE *f_random;

    f_random = fopen("/dev/urandom", "rb");
    fread(key_master, sizeof(unsigned char), 16, f_random);
    fclose(f_random);
    keywords_conuter.clear();

    return 1;
}

int DianaClient::update(const std::string& keyword, unsigned char *output,  unsigned int& c, unsigned char *bytes_to_enc_id,
        unsigned char *Kw)
{
    unsigned char *kw, *kw1, __buf_k[48];
    unsigned int counter;
    ConstrainedPRF c_prf;

    kw = __buf_k;
    kw1 = __buf_k + 16;

    _prf_F((const unsigned char *)keyword.c_str(), keyword.size(), __buf_k);

    if(keywords_conuter.find(keyword) == keywords_conuter.end())
        counter = 0;
    else
        counter = keywords_conuter[keyword]+1;

    c = counter;
    c_prf.Eval(kw, counter, kw1+16);
    keywords_conuter[keyword] = counter;

    SHA256(kw1, 32, output);
    if(bytes_to_enc_id != nullptr)
        SHA512(kw1, 32, bytes_to_enc_id);

    memcpy(Kw, kw, 16);

    return 1;
}

int DianaClient::trapdoor(const std::string& keyword, ConstrainedKey &trpdr_key, unsigned char *kw1_out)
{
    unsigned char *kw, *kw1, __buf_k[48];
    unsigned int counter;
    ConstrainedPRF c_prf;

    if(keywords_conuter.find(keyword) == keywords_conuter.end())
    {
        trpdr_key.current_permitted = 0u;
        memset(kw1_out, 0, 16);
        return 0;
    }
    else
        counter = keywords_conuter[keyword];

    kw = __buf_k;
    kw1 = __buf_k + 16;

    _prf_F((const unsigned char *)keyword.c_str(), keyword.size(), __buf_k);

    c_prf.Constrain(kw, counter, trpdr_key);

    memcpy(kw1_out, kw1, 16);

    return 1;
}

unsigned int DianaClient::get_keyword_counter(const std::string &keyword)
{
    return this->keywords_conuter[keyword];
}

int DianaClient::get_kw_and_kw1(const std::string &keyword, unsigned char *kw_out, unsigned char *kw1_out)
{
    unsigned char *kw, *kw1, __buf_k[48];

    kw = __buf_k;
    kw1 = __buf_k + 16;

    _prf_F((const unsigned char *)keyword.c_str(), keyword.size(), __buf_k);

    memcpy(kw_out, kw, 16);
    memcpy(kw1_out, kw1, 16);

    return 1;
}

void DianaClient::dump_data(FILE *f_out)
{
    unsigned long len_counter = this->keywords_conuter.size();
    unsigned long len_str;
    unsigned int count;

    fwrite(this->key_master, sizeof(char), 16, f_out);
    fwrite(&len_counter, sizeof(char), sizeof(len_counter), f_out);

    for(auto &it:this->keywords_conuter)
    {
        len_str = it.first.size();
        count = it.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(it.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }
}

void DianaClient::load_data(FILE *f_in)
{
    unsigned long len_counter;
    unsigned long len_str;
    unsigned int count;
    char buf1[500];

    this->keywords_conuter.clear();

    fread(this->key_master, sizeof(char), 16, f_in);
    fread(&len_counter, sizeof(char), sizeof(len_counter), f_in);

    for(unsigned long i=0; i<len_counter; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        buf1[len_str] = 0;

        fread(&count, sizeof(char), sizeof(count), f_in);

        keyword = buf1;
        this->keywords_conuter[keyword] = count;
    }
}

int DianaClient::_prf_F(const unsigned char *in, unsigned long len, unsigned char *out)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned int out_len;

    HMAC_Init_ex(ctx, this->key_master, 16, EVP_sha256(), nullptr);
    HMAC_Update(ctx, in, len);
    HMAC_Final(ctx, out, &out_len);
    HMAC_CTX_free(ctx);

    return 1;
}

int DianaServer::Setup()
{
    for(auto it=cipher_store.begin(); it!=cipher_store.end(); it++)
    {
        delete it->second;
    }

    cipher_store.clear();
    //cipher_store.reserve(300000);
    return 1;
}

int DianaServer::Save(unsigned char *label, unsigned char *data, int length)
{
    string _label;
    auto _data = new DianaData();

    memset(_data->ct, 0, 64);

    memcpy(_data->ct, data, length);

    _label.assign((char*)label, 32);
    _data->len = length;
    cipher_store[_label] = _data;

    return 1;
}

//the returned pointer must be freed.
int DianaServer::Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData *> &out)
{
    unsigned char buf1[64], buf2[64];
    string _label;
    ConstrainedPRF c_prf;

    for(unsigned int i=0; i <= trpder_key.current_permitted ;i++)
    {
        c_prf.Eval(trpder_key, i, buf1+16);

        memcpy(buf1, kw1, 16);
        SHA256(buf1, 32, buf2);
        _label.assign((char*)buf2, 32);

        if(cipher_store.find(_label)!=cipher_store.end())
        {
            auto _r = new DianaData();

            SHA512(buf1, 32, buf2);
            _r->len = 32;
            for(int j=0; j<32; j++)
                _r->ct[j] = cipher_store[_label]->ct[j] ^ buf2[j];

            out.emplace_back(_r);
        }
        else
           return 0;
    }

    return 1;
}

int DianaServer::SearchRange(ConstrainedKey &trpder_key, unsigned char *kw1, std::vector<DianaData *> &out)
{
    unsigned char buf1[64], buf2[64];
    string _label;
    ConstrainedPRF c_prf;

    for(unsigned int i=trpder_key.start; i <= trpder_key.end ; i++)
    {
        c_prf.Eval_range(trpder_key, i, buf1 + 16);

        memcpy(buf1, kw1, 16);
        SHA256(buf1, 32, buf2);
        _label.assign((char*)buf2, 32);

        if(cipher_store.find(_label)!=cipher_store.end())
        {
            SHA512(buf1, 32, buf2);
            auto _r = new DianaData();

            for(int j=0; j<64; j++)
                _r->ct[j] = cipher_store[_label]->ct[j] ^ buf2[j];

            out.emplace_back(_r);
        }
        else
            return 0;
    }
    return 1;
}

void DianaServer::dump_data(FILE *f_out)
{
    unsigned long len_db = this->cipher_store.size();
    unsigned long len_str;

    fwrite(&len_db, sizeof(len_db), 1, f_out);

    for(auto &itr:this->cipher_store)
    {
        len_str = itr.first.size();

        fwrite(&len_str, sizeof(len_str),1, f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&(itr.second->len), sizeof(itr.second->len), 1, f_out);
        fwrite(itr.second->ct, sizeof(char), itr.second->len, f_out);
    }
}

void DianaServer::load_data(FILE *f_in)
{
    unsigned long len_db;
    unsigned long len_str;
    char buf1[500];

    for(auto &itr:this->cipher_store)
        delete itr.second;

    this->cipher_store.clear();

    fread(&len_db, sizeof(len_db),1, f_in);

    for(unsigned long i=0; i<len_db; i++)
    {
        string label;
        auto d = new DianaData();

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);

        label.assign(buf1, len_str);
        fread(&(d->len), sizeof(d->len), 1, f_in);
        fread(d->ct, sizeof(char), d->len, f_in);

        this->cipher_store[label] = d;
    }
}

DianaServer::~DianaServer()
{
    for(auto &itr:this->cipher_store)
        delete itr.second;
}
