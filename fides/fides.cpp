//
// Created by Xu Peng on 2019/8/25.
//

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <set>
#include <string>
#include <list>
#include <iostream>

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
}

#include "fides.h"

using std::string;
using std::vector;
using std::unordered_map;
using std::cout;
using std::endl;
using std::set;
using std::list;

int FidesClient::Setup()
{
    FILE *f_rand = fopen("/dev/urandom", "rb");

    fread(this->K_master, sizeof(unsigned char), 16, f_rand);

    fclose(f_rand);

    this->sophos_clnt.Setup();
    this->Tw.clear();

    return 1;
}

int FidesClient::update(const std::string &keyword, const std::string &ind, FidesOp op, unsigned char *label,
                        unsigned char *IV, unsigned char *ciphertext)
{
    unsigned char Kw[32], _plain[68], _cipher[80], iv[16];
    AES_KEY aes_key;
    string keyword_with_tw;
    char tw[16];

    this->_gen_kw(keyword, Kw);

    sprintf(tw, "%u", this->Tw[keyword]);

    keyword_with_tw = keyword + tw;

    this->sophos_clnt.update(keyword_with_tw, label);

    memset(_plain, 0, 68);
    strncpy((char *) _plain, ind.c_str(), 68);
    _plain[64] = '\0';

    if (op == Fides_Add)
        _plain[65] = 1;
    else
        _plain[65] = 0;

    memset(_cipher, 0, 80);
    AES_set_encrypt_key(Kw, 128, &aes_key);
    RAND_bytes(iv, 16);
    memcpy(IV, iv, 16);
    AES_cbc_encrypt(_plain, _cipher, 68, &aes_key, iv, AES_ENCRYPT);
    memcpy(ciphertext, _cipher, 80);

    return 1;
}

int FidesClient::_gen_kw(const std::string &keyword, unsigned char *Kw)
{
    unsigned char buf1[80];

    memcpy(buf1, this->K_master, 16);
    SHA256((unsigned char *) keyword.c_str(), keyword.size(), buf1 + 16);
    memset(buf1 + 48, 0, 16);
    if (this->Tw.find(keyword) == this->Tw.end())
        this->Tw[keyword] = 0;

    sprintf((char *) buf1 + 48, "%u", this->Tw[keyword]);

    SHA256(buf1, 64, Kw);

    return 1;
}

int FidesClient::search_stage1(const std::string &keyword, unsigned char *kw, unsigned char *st, unsigned int &counter)
{
    unsigned char Kw[32];
    string keyword_with_tw;
    char tw[16];

    this->_gen_kw(keyword, Kw);

    sprintf(tw, "%u", this->Tw[keyword]);
    keyword_with_tw = keyword + tw;

    this->sophos_clnt.trapdoor(keyword_with_tw, kw, st, counter);

    return 1;
}

int FidesClient::search_stage2(const std::string &keyword, std::vector<std::string> &enc_data,
                               std::vector<std::string> &out)
{
    unsigned char Kw[32], _plain[80], iv[16];
    set<string> _ind_to_del;
    vector<string> _temp_ret;
    AES_KEY aes_key;

    _temp_ret.reserve(300000);

    this->_gen_kw(keyword, Kw);
    AES_set_decrypt_key(Kw, 128, &aes_key);

    for (const auto &a:enc_data)
    {
        memcpy(iv, a.c_str(), 16);
        AES_cbc_encrypt((unsigned char *) a.c_str() + 16, _plain, 80, &aes_key, iv, AES_DECRYPT);

        if (_plain[65] == 0)
            _ind_to_del.emplace(string((char *) _plain));
        else
            _temp_ret.emplace_back(string((char *) _plain));
    }

    for (auto it = _temp_ret.begin(); it != _temp_ret.end(); it++)
    {
        if (_ind_to_del.find(*it) == _ind_to_del.end())
        {
            out.emplace_back(*it);
        }
    }

    this->Tw[keyword] = this->Tw[keyword] + 1;

    return 1;
}

int FidesClient::get_pk(TdpPK *pk)
{
    return this->sophos_clnt.get_pk(pk);
}

void FidesClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long Tw_len = this->Tw.size();

    fwrite(&Tw_len, sizeof(char), sizeof(Tw_len), f_out);

    for (auto &itr:this->Tw)
    {
        unsigned long str_len = itr.first.size();
        unsigned int tw = itr.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&tw, sizeof(char), sizeof(tw), f_out);
    }

    fwrite(this->K_master, sizeof(char), 16, f_out);

    this->sophos_clnt.dump_data(f_out);

    fclose(f_out);
}

void FidesClient::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    char buf1[512];
    unsigned long tw_len, str_len;
    unsigned int tw;

    this->Tw.clear();

    fread(&tw_len, sizeof(char), sizeof(tw_len), f_in);

    for (unsigned long i = 0; i < tw_len; i++)
    {
        string keyword;

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;

        keyword = buf1;

        fread(&tw, sizeof(char), sizeof(tw), f_in);

        this->Tw[keyword] = tw;
    }

    fread(this->K_master, sizeof(char), 16, f_in);

    this->sophos_clnt.load_data(f_in);

    fclose(f_in);
}

int FidesClient::update_after_search(const std::string &keyword, std::vector<std::string> &inds,
                                     std::vector<std::string> &vec_label, std::vector<std::string> &vec_cipher)
{
    unsigned char label[32], cipher[100];
    for (auto &itr:inds)
    {
        string _l, _c;
        this->update(keyword, itr, Fides_Add, label, cipher, cipher + 16);
        _l.assign((char *) label, 32);
        _c.assign((char *) cipher, 96);
        vec_label.emplace_back(_l);
        vec_cipher.emplace_back(_c);
    }

    return 0;
}

int FidesServer::Setup()
{
    this->sophos_srv.Setup();
    return 1;
}

int FidesServer::save(unsigned char *label, unsigned char *IV, unsigned char *value)
{
    this->sophos_srv.save(label, IV, value);
    return 1;
}

int FidesServer::search(TdpPK *pk, unsigned char *kw, unsigned char *st, unsigned int counter,
                        std::vector<std::string> &out)
{
    this->sophos_srv.search(pk, kw, st, counter, out);
    return 1;
}

void FidesServer::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    this->sophos_srv.dump_data(f_out);

    fclose(f_out);
}

void FidesServer::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    this->sophos_srv.load_data(f_in);

    fclose(f_in);
}

int FidesServer::save(vector<std::string> &labels, vector<std::string> &ciphers)
{
    int count = labels.size();

    for (int i = 0; i < count; i++)
    {
        this->sophos_srv.save((unsigned char *) labels[i].c_str(), (unsigned char *) ciphers[i].c_str(),
                              (unsigned char *) ciphers[i].c_str() + 16);
    }

    return 0;
}
