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
#include <openssl/hmac.h>
#include <openssl/evp.h>
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

int DianaClient::update(const std::string& keyword, unsigned char *output)
{
    unsigned char Tw[16], __buf[32], *kw;
    unsigned int counter;
    ConstrainedPRF c_prf;

    kw = __buf;
    PRF_F_sha256(keyword.c_str(), keyword.size(), __buf);

    if(keywords_conuter.find(keyword) == keywords_conuter.end())
        counter = 0;
    else
        counter = keywords_conuter[keyword]+1;

    c_prf.Eval(kw, counter, Tw);
    keywords_conuter[keyword] = counter;
    memcpy(__buf, Tw, 16);
    SHA256(__buf, 32, output);

    return 1;
}

int DianaClient::trapdoor(const std::string& keyword, ConstrainedKey &trpdr_key, unsigned char *kw1_out)
{
    unsigned char __buf[32];
    int counter;
    ConstrainedPRF c_prf;

    if(keywords_conuter.find(keyword) == keywords_conuter.end())
    {
        trpdr_key.current_permitted = 0;
        memset(kw1_out, 0, 16);
        return 0;
    }

    PRF_F_sha256(keyword.c_str(), keyword.size(), __buf);

    counter = keywords_conuter[keyword];
    c_prf.Constrain(__buf, counter, trpdr_key);

    memcpy(kw1_out, __buf+16, 16);

    return 1;
}

void DianaClient::dump_data(FILE *f_out)
{
    unsigned long len_counter = this->keywords_conuter.size();
    unsigned long len_str;
    unsigned int count;

    fwrite(this->key_master, sizeof(char), 16, f_out);

    fwrite(&len_counter, sizeof(char), sizeof(len_counter), f_out);

    for(auto &itr:this->keywords_conuter)
    {
        len_str = itr.first.size();
        count = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }
}

void DianaClient::load_data(FILE *f_in)
{
    unsigned long len_counter, len_str;
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
        fread(&count, sizeof(char), sizeof(count), f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->keywords_conuter[keyword] = count;
    }
}

void DianaClient::PRF_F_sha256(const char *keyword, unsigned int len, unsigned char *out)
{
    unsigned int out_len;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, this->key_master, 16, EVP_sha256(), NULL);
    HMAC_Update(ctx, (const unsigned char*)keyword, len);
    HMAC_Final(ctx, out, &out_len);

    HMAC_CTX_free(ctx);
}

int DianaServer::Setup()
{
    for(auto it=cipher_store.begin(); it!=cipher_store.end(); it++)
    {
        delete it->second;
    }

    for(auto it=psk_store.begin(); it!=psk_store.end(); it++)
    {
        delete it->second->key;
        delete it->second;
    }

    cipher_store.clear();
    psk_store.clear();

    cipher_store.reserve(300000);
    psk_store.reserve(300000);

    return 1;
}

int DianaServer::Save(unsigned char *label, unsigned char *IV, unsigned char *cipher, PunTag &tag)
{
    string _label;
    auto _data = new DianaData();

    memcpy(_data->ct, cipher, 64);
    memcpy(_data->IV, IV, 16);
    _data->tag = tag;

    _label.assign((char*)label, 32);

    cipher_store[_label] = _data;

    return 1;
}

int DianaServer::Save(unsigned char *label, PuncturedKey *key, PunTag &tag)
{
    string _label;
    auto _data = new DianaDataDel();

    _data->key = new  PuncturedKey();
    *(_data->key) = *key;
    _data->tag = tag;

    _label.assign((char*)label, 32);

    psk_store[_label] = _data;

    return 1;
}

int DianaServer::Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData *> &out)
{
    unsigned char buf1[64], buf2[32];
    string _label;
    ConstrainedPRF c_prf;

    for(unsigned int i=0; i <= trpder_key.current_permitted ;i++)
    {
        c_prf.Eval(trpder_key, i, buf1);

        memcpy(buf1+16, kw1, 16);
        SHA256(buf1, 32, buf2);
        _label.assign((char*)buf2, 32);

        if(cipher_store.find(_label)!=cipher_store.end())
        {
            out.emplace_back(cipher_store[_label]);
        }
        else
           return 0;
    }

    return 1;
}

int DianaServer::Search(ConstrainedKey &trpder_key, unsigned char *kw1, std::vector<DianaDataDel *>& out)
{
    unsigned char buf1[64], buf2[32];
    string _label;
    ConstrainedPRF c_prf;

    for(unsigned int i=0; i<=trpder_key.current_permitted;i++)
    {
        c_prf.Eval(trpder_key, i, buf1);
        memcpy(buf1+16, kw1, 16);
        SHA256(buf1, 32, buf2);
        _label.assign((char*)buf2, 32);
        if(psk_store.find(_label)!=psk_store.end())
            out.emplace_back(psk_store[_label]);
        else
            return 0;
    }
    return 1;
}

void DianaServer::dump_data(FILE *f_out)
{
    unsigned long len_map, len_str;

    len_map = this->cipher_store.size();
    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);
    for(auto &itr:this->cipher_store)
    {
        len_str = itr.first.size();
        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(itr.second->ct, sizeof(char), 64, f_out);
        fwrite(itr.second->IV, sizeof(char), 16, f_out);
        itr.second->tag.dump_data(f_out);
    }

    len_map = this->psk_store.size();
    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);
    for(auto &itr:this->psk_store)
    {
        len_str = itr.first.size();
        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        itr.second->key->dump_data(f_out);
        itr.second->tag.dump_data(f_out);
    }
}

void DianaServer::load_data(FILE *f_in)
{
    unsigned long len_map, len_str;
    char buf1[500];

    for(auto &itr:this->cipher_store)
        delete itr.second;

    for(auto &itr:this->psk_store)
    {
        delete itr.second->key;
        delete itr.second;
    }

    this->cipher_store.clear();
    this->psk_store.clear();

    fread(&len_map, sizeof(char), sizeof(len_map), f_in);
    for(unsigned long i=0; i<len_map; i++)
    {
        string label;
        auto data = new DianaData();

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);

        fread(data->ct, sizeof(char), 64, f_in);
        fread(data->IV, sizeof(char), 16, f_in);
        data->tag.load_data(f_in);

        label.assign(buf1, len_str);
        this->cipher_store[label] = data;
    }

    fread(&len_map, sizeof(char), sizeof(len_map), f_in);
    for(unsigned long i=0; i<len_map; i++)
    {
        string label;
        auto data = new DianaDataDel();
        data->key = new PuncturedKey();

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);

        data->key->load_data(f_in);
        data->tag.load_data(f_in);

        label.assign(buf1, len_str);
        this->psk_store[label] = data;

    }
}

DianaServer::~DianaServer()
{
    for(auto &itr:this->cipher_store)
        delete itr.second;
    for(auto &itr:this->psk_store)
    {
        delete itr.second->key;
        delete itr.second;
    }

}

