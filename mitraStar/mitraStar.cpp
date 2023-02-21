//
// Created by spiraldox on 8/26/19.
//

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <iostream>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
}

#include "mitraStar.h"

using std::string;
using std::vector;
using std::list;
using std::set;

int MitraStarClient::Setup()
{
    FILE *f_rand = fopen("/dev/urandom", "rb");

    fread(this->k_master, sizeof(unsigned char), 16, f_rand);

    fclose(f_rand);

    this->FileCnt.clear();
    this->SrcCnt.clear();

    return 1;
}

int MitraStarClient::update(const std::string &keyword, const std::string &ind, MitraStarOp op,
                            unsigned char *label, unsigned char *ciphertext)
{
    char str[68];
    unsigned char srckey[16];

    if (this->FileCnt.find(keyword) == this->FileCnt.end())
        this->FileCnt[keyword] = 0;
    if (this->SrcCnt.find(keyword) == this->SrcCnt.end())
        this->SrcCnt[keyword] = 0;

    this->FileCnt[keyword] = this->FileCnt[keyword] + 1;
    this->_prf_gen_srckey(this->SrcCnt[keyword], srckey);
    this->_prf_gen_label(srckey, keyword, this->FileCnt[keyword], label);
    this->_prf_gen_ciphertext(srckey, keyword, this->FileCnt[keyword], ciphertext);

    strncpy(str, ind.c_str(), 65);
    str[64] = '\0';

    for (int i = 0; i < 65; i++)
        ciphertext[i] = ciphertext[i] ^ (unsigned char) str[i];

    if (op == Mitra_Add)
        ciphertext[65] = ciphertext[65] ^ 0xffu;
    else
        ciphertext[65] = ciphertext[65] ^ 0x00u;

    return 1;
}

int MitraStarClient::_prf_gen_srckey(unsigned int c, unsigned char *srckey)
{
    unsigned char buf[128];
    unsigned int tmp = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, this->k_master, 16, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) &c, sizeof(c));
    HMAC_Final(ctx, buf, &tmp);

    HMAC_CTX_free(ctx);

    memcpy(srckey, buf, 16);
    return 1;
}

int
MitraStarClient::_prf_gen_label(unsigned char *srckey, const std::string &keyword, unsigned int c, unsigned char *label)
{
    unsigned int tmp = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, srckey, 16, EVP_sha256(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) &c, sizeof(c));
    HMAC_Update(ctx, (const unsigned char *) &tmp, sizeof(tmp));
    HMAC_Final(ctx, label, &tmp);

    HMAC_CTX_free(ctx);

    return 1;
}

int MitraStarClient::_prf_gen_ciphertext(unsigned char *srckey, const std::string &keyword, unsigned int c,
                                         unsigned char *ciphertext)
{
    unsigned char buf[128];
    unsigned int tmp = 1;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, srckey, 16, EVP_sha512(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) &c, sizeof(c));
    HMAC_Update(ctx, (const unsigned char *) &tmp, sizeof(tmp));
    HMAC_Final(ctx, buf, &tmp);

    HMAC_CTX_free(ctx);

    ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, srckey, 16, EVP_sha224(), nullptr);
    HMAC_Update(ctx, buf, 64);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) &c, sizeof(c));
    HMAC_Update(ctx, (const unsigned char *) &tmp, sizeof(tmp));
    HMAC_Final(ctx, buf + 64, &tmp);

    HMAC_CTX_free(ctx);

    memcpy(ciphertext, buf, 66);

    return 1;
}

int MitraStarClient::search_stage1(const std::string &keyword, std::vector<std::string> &tlist)
{
    unsigned char label[32];
    unsigned char srckey[16];

    if (this->FileCnt.find(keyword) == this->FileCnt.end())
        this->FileCnt[keyword] = 0;
    if (this->SrcCnt.find(keyword) == this->SrcCnt.end())
        this->SrcCnt[keyword] = 0;

    this->_prf_gen_srckey(this->SrcCnt[keyword], srckey);
    for (unsigned int i = 1; i <= this->FileCnt[keyword]; i++)
    {
        string _t;
        this->_prf_gen_label(srckey, keyword, i, label);
        _t.assign((char *) label, 32);
        tlist.emplace_back(_t);
    }

    return 1;
}

int MitraStarClient::search_stage2(const std::string &keyword, std::vector<std::string> &Fw,
                                   std::vector<std::string> &search_ret, std::vector<std::string> &labels,
                                   std::vector<std::string> &ciphers)
{
    unsigned char buf1[68], buf2[68];
    vector<string> _temp_ret;
    set<string> _id_to_del;
    unsigned int counter = 1;
    unsigned char srckey[16];
    unsigned char label[32], ciphertext[68];

    _temp_ret.reserve(300000);

    this->_prf_gen_srckey(this->SrcCnt[keyword], srckey);
    for (const auto &a:Fw)
    {
        this->_prf_gen_ciphertext(srckey, keyword, counter, buf1);
        for (int i = 0; i < 66; i++)
            buf2[i] = buf1[i] ^ (unsigned char) a.c_str()[i];
        if (buf2[65] == 0xff)
            _temp_ret.emplace_back(string((char *) buf2));
        else
            _id_to_del.emplace(string((char *) buf2));
        counter++;
    }

    //decryption and re-encryption
    this->FileCnt[keyword] = 0;
    this->SrcCnt[keyword] = this->SrcCnt[keyword] + 1;

    for (auto it = _temp_ret.begin(); it != _temp_ret.end(); it++)
    {
        if (_id_to_del.find(*it) == _id_to_del.end())
        {
            search_ret.emplace_back(*it);
        }
    }
    this->update(keyword, search_ret, labels, ciphers);

    return 1;
}

int MitraStarClient::update(const std::string &keyword, std::vector<std::string> &ids,
           std::vector<std::string> &labels, std::vector<std::string> &ciphers)
{
    char str[68];
    unsigned char srckey[16], label[32], ciphertext[66];
    unsigned int count = 0;

    this->_prf_gen_srckey(this->SrcCnt[keyword], srckey);

    for (auto it = ids.begin(); it != ids.end(); it++)
    {
        string _l, _c;
        count += 1;

        this->_prf_gen_label(srckey, keyword, count, label);
        this->_prf_gen_ciphertext(srckey, keyword, count, ciphertext);

        for (int i = 0; i < 65; i++)
            ciphertext[i] = ciphertext[i] ^ (unsigned char) it->c_str()[i];

        ciphertext[65] = ciphertext[65] ^ 0xffu;
        _l.assign((char *)label, 32);
        _c.assign((char *)ciphertext, 66);
        labels.emplace_back(_l);
        ciphers.emplace_back(_c);
    }

    this->FileCnt[keyword] = count;
    return 1;
}

void MitraStarClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long count_len = this->FileCnt.size();
    unsigned long str_len;
    unsigned int count;

    fwrite(this->k_master, sizeof(unsigned char), 16, f_out);
    fwrite(&count_len, sizeof(unsigned char), sizeof(count_len), f_out);

    for (auto &a:this->FileCnt)
    {
        str_len = a.first.size();
        count = a.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(a.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }
    count_len = this->SrcCnt.size();
    fwrite(&count_len, sizeof(unsigned char), sizeof(count_len), f_out);
    for (auto &a: this->SrcCnt)
    {
        str_len = a.first.size();
        count = a.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(a.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }

    fclose(f_out);
}

void MitraStarClient::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long count_len;
    unsigned long str_len;
    unsigned int count;
    char buf1[512];

    this->FileCnt.clear();
    this->SrcCnt.clear();

    fread(this->k_master, sizeof(char), 16, f_in);
    fread(&count_len, sizeof(char), sizeof(count_len), f_in);

    for (unsigned long i = 0; i < count_len; i++)
    {
        string keyword;
        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;
        keyword = buf1;

        fread(&count, sizeof(char), sizeof(count), f_in);

        this->FileCnt[keyword] = count;
    }
    fread(&count_len, sizeof(char), sizeof(count_len), f_in);
    for (unsigned i = 0; i <count_len; i++)
    {
        string keyword;
        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;
        keyword = buf1;

        fread(&count, sizeof(char), sizeof(count), f_in);

        this->SrcCnt[keyword] = count;
    }

    fclose(f_in);
}

int MitraStarServer::Setup()
{
    this->cipher_db.clear();

    return 1;
}

int MitraStarServer::save(unsigned char *label, unsigned char *cipher)
{
    string _l, _v;

    _l.assign((char *) label, 32);
    _v.assign((char *) cipher, 66);

    this->cipher_db[_l] = _v;

    return 1;
}

int MitraStarServer::save(const std::vector<std::string> &labels, const std::vector<std::string> &ciphers)
{
    int count = labels.size();

    for(int i=0; i<count; i++)
    {
        this->cipher_db[labels[i]] = ciphers[i];
    }

    return 1;
}

int MitraStarServer::search(std::vector<std::string> &tlist, std::vector<std::string> &Fw)
{
    for (const auto &a:tlist)
    {
        Fw.emplace_back(this->cipher_db[a]);
        this->cipher_db.erase(a);
    }

    return 1;
}

void MitraStarServer::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long db_len = this->cipher_db.size();
    unsigned long str_len;

    fwrite(&db_len, sizeof(char), sizeof(db_len), f_out);

    for (auto &itr:this->cipher_db)
    {
        str_len = itr.first.size();
        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), str_len, f_out);

        str_len = itr.second.size();
        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.second.c_str(), sizeof(char), str_len, f_out);
    }

    fclose(f_out);
}

void MitraStarServer::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long count;
    unsigned long str_len;
    char buf1[512];

    this->cipher_db.clear();

    fread(&count, sizeof(char), sizeof(count), f_in);

    for (unsigned long i = 0; i < count; i++)
    {
        string l, v;
        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        l.assign(buf1, str_len);

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        v.assign(buf1, str_len);

        this->cipher_db[l] = v;
    }

    fclose(f_in);
}
