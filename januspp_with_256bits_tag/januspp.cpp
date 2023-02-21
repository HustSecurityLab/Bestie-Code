//
// Created by Xu Peng on 2019/8/16.
//

#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/hmac.h>
}

#include "januspp.h"

using std::string;
using std::vector;
using std::cout;
using std::endl;

int JanusPPServer::Setup()
{
    diana_srv.Setup();
    diana_srv_del.Setup();
    return 0;
}

int JanusPPServer::SaveCipher(unsigned char *label, unsigned char *IV, unsigned char *ct, PunTag &tag)
{
    return diana_srv.Save(label, IV, ct, tag);
}

int JanusPPServer::DeleteCipher(unsigned char *label, PuncturedKey *psk, PunTag &tag)
{
    return diana_srv_del.Save(label, psk, tag);
}

int JanusPPServer::Search(ConstrainedKey &key, unsigned char *kw1, ConstrainedKey &key_del, unsigned char *kw1_del,
                          unsigned char *msk, int d, std::vector<std::string> &output)
{
    vector<DianaDataDel *> srch_data_del;
    vector<DianaData *> srch_data;
    PunEncryptionKey punc_key;
    PunEncryption punc_enc;
    char out_str[80];

    srch_data.reserve(300000);
    srch_data.reserve(300000);

    diana_srv.Search(key, kw1, srch_data);
    diana_srv_del.Search(key_del, kw1_del, srch_data_del);

    punc_key.max_deletion = d;
    punc_key.current_deleted = srch_data_del.size();

    for (auto _d:srch_data_del)
    {
        auto _k = new PuncturedKey();
        *_k = *_d->key;
        punc_key.key_data.emplace_back(_k);
    }
    if (punc_key.current_deleted < punc_key.max_deletion)
        punc_key.key_data.emplace_back(new PuncturedKey(msk));
    for (DianaData *c:srch_data)
    {
        if (punc_enc.decrypt(&punc_key, c->tag, c->IV, c->ct, out_str) == 1)
        {
            output.emplace_back(string(out_str));
        }
    }

    return 1;
}

void JanusPPServer::dump_data(const std::string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    this->diana_srv.dump_data(f_out);
    this->diana_srv_del.dump_data(f_out);

    fclose(f_out);
}

void JanusPPServer::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    this->diana_srv.load_data(f_in);
    this->diana_srv_del.load_data(f_in);

    fclose(f_in);
}

int JanusPPClient::Setup()
{
    FILE *f_rand;

    f_rand = fopen("/dev/urandom", "rb");
    fread(ks, sizeof(unsigned char), 16, f_rand);
    fread(kt, sizeof(unsigned char), 16, f_rand);
    fclose(f_rand);

    this->deleting_support = MAX_DELETESUPPORT;
    this->sc.clear();
    this->del.clear();
    for (const auto a:this->msk)
        delete[] a.second;
    this->msk.clear();

    for (const auto a:this->psk)
        delete[] a.second;
    this->psk.clear();

    this->diana_clnt.Setup();
    this->diana_clnt_del.Setup();
    return 0;
}

PunTag JanusPPClient::generate_tag(const std::string &keyword, const std::string &ind)
{
    string data_to_hash;
    PunTag ret;

    this->_prf_f(keyword, ind, ret.get_data_ptr());

    return ret;
}

int JanusPPClient::Add(const std::string &keyword, unsigned char *label, const std::string &ind, unsigned char *IV,
                       unsigned char *ct, PunTag &tag)
{
    PunEncryption spe;
    char id_to_encrypt[68];//id is 64 bytes hexhash
    char number[16];

    _init_keyword_state(keyword);

    PunEncryptionKey spe_key(this->deleting_support, this->msk[keyword]);

    tag = generate_tag(keyword, ind);
    memset(id_to_encrypt, 0, 68);
    strncpy((char *) id_to_encrypt, ind.c_str(), 68);
    id_to_encrypt[64] = '\0';
    spe.encrypt_with_low_storage(&spe_key, tag, id_to_encrypt, IV, ct);

    //generate ciphertext of Diana
    sprintf(number, "%d", this->sc[keyword]);
    this->diana_clnt.update(keyword + number, label);

    return 1;
}

int JanusPPClient::_init_keyword_state(const std::string &keyword)
{
    if (this->msk.find(keyword) == this->msk.end())
    {
        auto _msk = new unsigned char[16];
        auto _psk = new unsigned char[16];
        FILE *f_rand = fopen("/dev/urandom", "rb");
        fread(_msk, sizeof(char), 16, f_rand);
        memcpy(_psk, _msk, 16);
        fclose(f_rand);
        this->msk[keyword] = _msk;
        this->psk[keyword] = _psk;
        this->sc[keyword] = 0;
        this->del[keyword] = deleting_support;
    }
    return 1;
}

int
JanusPPClient::Delete(const std::string &keyword, unsigned char *label, const std::string &ind, PuncturedKey *psk_out,
                      PunTag &tag)
{
    PunEncryption spe;
    unsigned char buf1[32];
    char number[16];

    _init_keyword_state(keyword);
    if (this->del[keyword] <= 0)
        return 0;
    tag = generate_tag(keyword, ind);
    spe.incremental_punc(this->psk[keyword], tag, psk_out, buf1);

    memcpy(this->psk[keyword], buf1, 16);

    //generate ciphertext of Diana
    sprintf(number, "%d", this->sc[keyword]);
    this->diana_clnt_del.update(keyword + number, label);

    this->del[keyword] = this->del[keyword] - 1;

    return 1;
}

int JanusPPClient::trapdoor(const std::string &keyword, unsigned char *msk_out, ConstrainedKey *trpd,
                            unsigned char *kw1, ConstrainedKey *trpd_del, unsigned char *kw1_del)
{
    char number[16];
    FILE *f_rand = fopen("/dev/urandom", "rb");

    if (this->msk.find(keyword) == this->msk.end())
    {
        fclose(f_rand);
        return 0;
    }
    memcpy(msk_out, this->psk[keyword], 16);

    sprintf(number, "%d", this->sc[keyword]);
    this->diana_clnt.trapdoor(keyword + number, *trpd, kw1);
    this->diana_clnt_del.trapdoor(keyword + number, *trpd_del, kw1_del);

    this->del[keyword] = deleting_support;
    this->sc[keyword] = this->sc[keyword] + 1;
    fread(this->msk[keyword], sizeof(char), 16, f_rand);
    fclose(f_rand);
    memcpy(this->psk[keyword], this->msk[keyword], 16);

    return 1;
}

void JanusPPClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long len_map, len_str;
    int map_data;

    fwrite(this->kt, sizeof(char), 16, f_out);
    fwrite(this->ks, sizeof(char), 16, f_out);

    //sc
    len_map = this->sc.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr:this->sc)
    {
        len_str = itr.first.size();
        map_data = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&map_data, sizeof(char), sizeof(map_data), f_out);
    }

    //del
    len_map = this->del.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr:this->del)
    {
        len_str = itr.first.size();
        map_data = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&map_data, sizeof(char), sizeof(map_data), f_out);
    }

    //msk
    len_map = this->msk.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr:this->msk)
    {
        len_str = itr.first.size();

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(itr.second, sizeof(char), 16, f_out);
    }

    //psk
    len_map = this->psk.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr:this->psk)
    {
        len_str = itr.first.size();

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(itr.second, sizeof(char), 16, f_out);
    }

    fwrite(&(this->deleting_support), sizeof(char), sizeof(this->deleting_support), f_out);

    this->diana_clnt.dump_data(f_out);
    this->diana_clnt_del.dump_data(f_out);

    fclose(f_out);
}

void JanusPPClient::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long len_map, len_str;
    char buf1[500];
    int map_data;

    this->sc.clear();
    this->del.clear();

    for (auto &itr:this->msk)
        delete[] itr.second;

    for (auto &itr:this->psk)
        delete[] itr.second;

    this->msk.clear();
    this->psk.clear();

    fread(this->kt, sizeof(char), 16, f_in);
    fread(this->ks, sizeof(char), 16, f_in);

    //sc
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(&map_data, sizeof(char), sizeof(map_data), f_in);
        buf1[len_str] = 0;
        keyword = buf1;
        this->sc[keyword] = map_data;
    }

    //del
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(&map_data, sizeof(char), sizeof(map_data), f_in);
        buf1[len_str] = 0;
        keyword = buf1;
        this->del[keyword] = map_data;
    }

    //msk
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;
        auto data = new unsigned char[16];
        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(data, sizeof(char), 16, f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->msk[keyword] = data;
    }

    //psk
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;
        auto data = new unsigned char[16];

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(data, sizeof(char), 16, f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->psk[keyword] = data;
    }

    fread(&(this->deleting_support), sizeof(char), sizeof(this->deleting_support), f_in);

    this->diana_clnt.load_data(f_in);
    this->diana_clnt_del.load_data(f_in);

    fclose(f_in);
}

JanusPPClient::~JanusPPClient()
{
    for (auto &itr:this->msk)
        delete[] itr.second;

    for (auto &itr:this->psk)
        delete[] itr.second;
}

int JanusPPClient::_prf_f(const std::string &keyword, const std::string &ind, unsigned char *data)
{
    unsigned int out_len;
    HMAC_CTX *ctx = HMAC_CTX_new();

    HMAC_Init_ex(ctx, this->kt, 16, EVP_sha256(), NULL);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    HMAC_Update(ctx, (const unsigned char *) ind.c_str(), ind.size());
    HMAC_Final(ctx, data, &out_len);
    HMAC_CTX_free(ctx);

    return out_len;
}
