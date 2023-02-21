//
// Created by spiraldox on 8/27/19.
//

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <list>
#include <exception>
#include <thread>
//#include <mutex>
#include <functional>
#include <set>
#include <unordered_set>
#include <chrono>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <pthread.h>
#include "unistd.h"
}

#include "bestie.h"

using namespace std;

static void print_hex(const unsigned char *data, unsigned long len)
{
    for (unsigned long i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int BestieClient::Setup()
{
    FILE *f_rand = fopen("/dev/urandom", "rb");

    fread(this->k_aes, sizeof(unsigned char), 16, f_rand);
    fread(this->s, sizeof(unsigned char), 16, f_rand);
    fclose(f_rand);

    this->count.clear();
    return 1;
}

int
BestieClient::update(const std::string &keyword, const std::string &ind, BestieOp op, unsigned char *L, unsigned char *D,
                     unsigned char *IV, unsigned char *C)
{
    unsigned char K[32], K_1[32], cip_id[32], buf[64];
    unsigned int cnt_upd;

    if (this->count.find(keyword) == this->count.end())
    {
        BestieCounter _c = {0, 0};
        this->count[keyword] = _c;
    }

    this->count[keyword].cnt_upd = this->count[keyword].cnt_upd + 1;
    cnt_upd = this->count[keyword].cnt_upd;

    this->_prf_F(keyword, this->count[keyword].cnt_srch, K);
    this->_prf_F(keyword, 0, K_1, true);

    _hash_H(K, cnt_upd, buf);
    memcpy(L, buf, 32);
    memcpy(D, buf + 32, 32);

    //output is 36 bytes
    _hash_G(K_1, keyword, ind, cip_id);
    if (op == Bestie_Add)
        cip_id[0] = 0xff;
    else
        cip_id[0] = 0x00;
    for (int i = 0; i < 32; i++)
        D[i] = D[i] ^ cip_id[i];

    //output is 64 bytes
    this->_encrypt_id(ind, IV, C);

    return 1;
}

int BestieClient::_prf_F(const std::string &keyword, unsigned int c, unsigned char *out, bool is_1)
{
    HMAC_CTX *ctx = HMAC_CTX_new();
    unsigned int out_len;
    char buffer[32];

    HMAC_Init_ex(ctx, this->s, 16, EVP_sha224(), nullptr);
    HMAC_Update(ctx, (const unsigned char *) keyword.c_str(), keyword.size());
    if (is_1)
        sprintf(buffer, "--111");
    else
        sprintf(buffer, "::%u", c);

    HMAC_Update(ctx, (unsigned char *) buffer, strlen(buffer));
    HMAC_Final(ctx, out, &out_len);

    HMAC_CTX_free(ctx);

    return 1;
}

int BestieClient::_encrypt_id(const std::string &ind, unsigned char *IV, unsigned char *c)
{
    unsigned char buf1[68], iv[16];
    AES_KEY aes_key;

    memset(buf1, 0, 68);
    RAND_bytes(iv, 16);
    memcpy(IV, iv, 16);
    strncpy((char *) buf1, ind.c_str(), 68);
    buf1[64] = '\0';

    memset(c, 0, 64);
    AES_set_encrypt_key(this->k_aes, 128, &aes_key);
    AES_cbc_encrypt(buf1, c, 64, &aes_key, iv, AES_ENCRYPT);

    return 1;
}

int BestieClient::_hash_G(unsigned char *K, const std::string &keyword, const std::string &ind, unsigned char *out)
{
    string _s = keyword + ind;
    EVP_MD_CTX *mdctx;
    unsigned int digest_len;

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, K, 16);
    EVP_DigestUpdate(mdctx, (const unsigned char *) _s.c_str(), _s.size());
    EVP_DigestFinal_ex(mdctx, out, &digest_len);

    EVP_MD_CTX_destroy(mdctx);

    if (digest_len != 32)
        return -1;

    return 1;
}

int BestieClient::_hash_H(unsigned char *K, unsigned int c, unsigned char *out)
{
    unsigned char buf1[32], buf2[32];

    memset(buf1, 0, 32);
    memcpy(buf1, K, 16);
    sprintf((char *) (buf1 + 16), "::%u", c);

    SHA512(buf1, 32, out);

    return 1;
}

int
BestieClient::trapdoor(const std::string &keyword, unsigned int &cnt_upd, unsigned char *K, unsigned char *loc_grp)
{
    BestieCounter c = {0, 0};
    unsigned char K_1[32];

    if (this->count.find(keyword) == this->count.end())
        return 0;

    c = this->count[keyword];

    this->_prf_F(keyword, c.cnt_srch, K);
    this->_prf_F(keyword, 0, K_1, true);

    c.cnt_srch = c.cnt_srch + 1;
    cnt_upd = c.cnt_upd;
    c.cnt_upd = 0;

    this->count[keyword] = c;

    this->_hash_G(K_1, keyword, "", loc_grp);

    return 1;
}

int BestieClient::decrypt(std::vector<std::string> &enc_ind, std::vector<std::string> &result)
{
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char buf1[80];

    AES_set_decrypt_key(this->k_aes, 128, &aes_key);
    buf1[64] = 0;
    for (const auto &a:enc_ind)
    {
        memcpy(iv, a.c_str(), 16);
        AES_cbc_encrypt((unsigned char *) a.c_str() + 16, buf1, 64, &aes_key, iv, AES_DECRYPT);
        result.emplace_back(string((char *) buf1));
    }

    return 1;
}

void BestieClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    unsigned long cout_size = this->count.size();

    fwrite(&cout_size, sizeof(char), sizeof(cout_size), f_out);

    for (auto &itr:this->count)
    {
        unsigned long len = itr.first.size();

        fwrite(&len, sizeof(char), sizeof(len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len, f_out);

        fwrite(&(itr.second.cnt_srch), sizeof(char), sizeof(unsigned int), f_out);
        fwrite(&(itr.second.cnt_upd), sizeof(char), sizeof(unsigned int), f_out);
    }

    fwrite(this->k_aes, sizeof(char), 16, f_out);
    fwrite(this->s, sizeof(char), 16, f_out);

    fclose(f_out);
}

void BestieClient::load_data(const std::string &filename)
{
    this->count.clear();

    FILE *f_in = fopen(filename.c_str(), "rb");
    char buf[512];

    unsigned long count_len;

    fread(&count_len, sizeof(char), sizeof(count_len), f_in);

    for (unsigned long i = 0; i < count_len; i++)
    {
        memset(buf, 0, 512);
        string label;
        BestieCounter c = {0, 0};

        unsigned long len;
        fread(&len, sizeof(char), sizeof(len), f_in);
        fread(buf, sizeof(char), len, f_in);
        label = buf;

        fread(&(c.cnt_srch), sizeof(char), sizeof(unsigned int), f_in);
        fread(&(c.cnt_upd), sizeof(char), sizeof(unsigned int), f_in);

        this->count[label] = c;
    }

    fread(this->k_aes, sizeof(char), 16, f_in);
    fread(this->s, sizeof(char), 16, f_in);

    fclose(f_in);
}

int BestieClient::decrypt(std::unordered_map<std::string, ReturnedCipher> &enc_ind, std::vector<std::string> &result)
{
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char buf1[80];

    AES_set_decrypt_key(this->k_aes, 128, &aes_key);
    buf1[64] = 0;
    for (const auto &a:enc_ind)
    {
        memcpy(iv, a.second.IV, 16);
        AES_cbc_encrypt(a.second.C, buf1, 64, &aes_key, iv, AES_DECRYPT);
        result.emplace_back(string((char *) buf1));
    }
    return 0;
}

int BestieServer::Setup()
{
    for (auto &a:this->cipher_db)
        delete a.second;
    this->cipher_db.clear();
    this->GRP.clear();

    if_cleaning = false;
    return 1;
}

int BestieServer::save(unsigned char *label, unsigned char *D, unsigned char *IV, unsigned char *C)
{
    string _l;
    BestieCipher *_c;

    if (if_cleaning)
        pthread_join(p_clean_thread, nullptr);
    if_cleaning = false;

    _l.assign((char *) label, 32);
    _c = new BestieCipher();

    memcpy(_c->D, D, 32);
    memcpy(_c->IV, IV, 16);
    memcpy(_c->C, C, 64);

    if (this->cipher_db.find(_l) != this->cipher_db.end())
        delete this->cipher_db[_l];
    this->cipher_db[_l] = _c;

    return 1;
}

int BestieServer::search(unsigned int cnt_upd, unsigned char *K, unsigned char *loc_grp, std::vector<std::string> &ret)
{
    unsigned char H_rslt[36], buf[80];
    std::unordered_set<string> D;
    std::vector<BestieCipher *> T;
    std::vector<string> L;
    string _l_grp;
    _l_grp.assign((char *) loc_grp, 32);
    std::unordered_map<string, string> &grp = this->GRP[_l_grp];

    D.reserve(300000);
    T.reserve(300000);
    auto start = chrono::steady_clock::now();
    for (unsigned int i = cnt_upd; i > 0; i--)
    {
        string _l;
        _hash_H(K, i, buf);
        _l.assign((char *) buf, 32);
        BestieCipher *p_c = this->cipher_db[_l];
        for (int j = 0; j < 32; j++)
            H_rslt[j] = p_c->D[j] ^ buf[j + 32];

        if (H_rslt[0] == 0) //del
        {
            string _l1;
            _l1.assign((char *) H_rslt + 1, 31);
            D.emplace(_l1);
            grp.erase(_l1);
        }
        else if (H_rslt[0] == 0xff) //add
        {
            string _l1;
            _l1.assign((char *) H_rslt + 1, 31);
            if (D.find(_l1) == D.end())
            {
                auto _c = new BestieCipher();
                memcpy(_c->D, H_rslt + 1, 31);
                memcpy(_c->C, p_c->C, 64);
                memcpy(_c->IV, p_c->IV, 16);
                T.emplace_back(_c);
            }
        }
        else
        {
            cout << "search process error, data damaged" << endl;
        }
        this->cipher_db.erase(_l);
        delete p_c;
    }
    auto end = chrono::steady_clock::now();
    chrono::duration<double, std::micro> elapsed = end - start;

    start = chrono::steady_clock::now();
    for (auto &it:grp)
    {
        ret.emplace_back(it.second);
    }
    for (auto it = T.begin(); it != T.end(); it++)
    {
        string _l;
        string _c;
        _l.assign((char *) (*it)->D, 31);
        memcpy(buf, (*it)->IV, 16);
        memcpy(buf + 16, (*it)->C, 64);
        _c.assign((char *) buf, 80);
        ret.emplace_back(_c);

        grp[_l] = _c;
    }
    end = chrono::steady_clock::now();
    elapsed = end - start;
    for (auto it = T.begin(); it != T.end(); it++)
        delete *it;

    return 1;
}

int BestieServer::_hash_H(unsigned char *K, unsigned int c, unsigned char *out)
{
    unsigned char buf1[32], buf2[32];

    memset(buf1, 0, 32);
    memcpy(buf1, K, 16);
    sprintf((char *) (buf1 + 16), "::%u", c);

    SHA512(buf1, 32, out);

    return 1;
}

void BestieServer::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    unsigned long db_len = cipher_db.size();

    fwrite(&db_len, sizeof(char), sizeof(db_len), f_out);

    for (auto &itr:this->cipher_db)
    {
        unsigned long len = itr.first.size();

        fwrite(&len, sizeof(char), sizeof(len), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len, f_out);

        fwrite(itr.second->D, sizeof(char), 32, f_out);
        fwrite(itr.second->IV, sizeof(char), 16, f_out);
        fwrite(itr.second->C, sizeof(char), 64, f_out);
    }

    unsigned long grp_len = this->GRP.size();

    fwrite(&grp_len, sizeof(char), sizeof(grp_len), f_out);

    for (auto &itr_grp:this->GRP)
    {
        unsigned long len = itr_grp.first.size();

        fwrite(&len, sizeof(char), sizeof(len), f_out);
        fwrite(itr_grp.first.c_str(), sizeof(char), len, f_out);

        unsigned long buc_len = itr_grp.second.size();

        fwrite(&buc_len, sizeof(char), sizeof(buc_len), f_out);

        for (auto &itr_buc:itr_grp.second)
        {
            unsigned long data_len = itr_buc.first.size();

            fwrite(&data_len, sizeof(char), sizeof(data_len), f_out);
            fwrite(itr_buc.first.c_str(), sizeof(char), data_len, f_out);

            data_len = itr_buc.second.size();

            fwrite(&data_len, sizeof(char), sizeof(data_len), f_out);
            fwrite(itr_buc.second.c_str(), sizeof(char), data_len, f_out);
        }
    }
    fclose(f_out);
}

void BestieServer::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    char buf1[512];

    for (auto &it:this->cipher_db)
        delete it.second;

    this->cipher_db.clear();

    unsigned long len;

    fread(&len, sizeof(char), sizeof(len), f_in);

    for (unsigned long i = 0; i < len; i++)
    {
        unsigned long str_len;
        string label;
        auto *c = new BestieCipher();

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        label.assign(buf1, str_len);

        fread(c->D, sizeof(char), 32, f_in);
        fread(c->IV, sizeof(char), 16, f_in);
        fread(c->C, sizeof(char), 64, f_in);

        this->cipher_db[label] = c;
    }

    fread(&len, sizeof(char), sizeof(len), f_in);

    for (unsigned long i = 0; i < len; i++)
    {
        decltype(string().size()) str_len;
        string grp_label;
        unordered_map<string, string> grp;

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);

        grp_label.assign(buf1, str_len);

        decltype(this->cipher_db.size()) buc_len;

        fread(&buc_len, sizeof(char), sizeof(buc_len), f_in);

        for (unsigned long j = 0; j < buc_len; j++)
        {
            decltype(string().size()) data_len;
            string l, v;

            fread(&data_len, sizeof(char), sizeof(data_len), f_in);
            fread(buf1, sizeof(char), data_len, f_in);
            l.assign(buf1, data_len);

            fread(&data_len, sizeof(char), sizeof(data_len), f_in);
            fread(buf1, sizeof(char), data_len, f_in);
            v.assign(buf1, data_len);

            grp[l] = v;
        }

        this->GRP[grp_label] = grp;
    }
    fclose(f_in);
}

int BestieServer::search_in_parallel(unsigned int cnt_upd, unsigned char *K, unsigned char *loc_grp,
                                     std::vector<std::string> &ret, int num_thread)
{
    //auto start = chrono::steady_clock::now();
    pthread_mutex_lock(&mutex_CDB);

    _num_t = num_thread > cnt_upd ? cnt_upd : num_thread;
    unordered_map<string, unsigned int> D;
    unsigned int avg_num = cnt_upd / _num_t;
    unsigned int thread_cnt = 0;

    //D.reserve(30000);

    this->_D = &D;
    if (_num_t > 64)
        return 0;

    for (unsigned int i = 0; i < _num_t; i++)
    {
        _search_thread_arg[i]._this = this;
        _search_thread_arg[i].D = &D;
        _search_thread_arg[i].K = K;
    }

    for (unsigned int i = 0; i < _num_t - 1; i++)
    {
        _search_thread_arg[i].start = i * avg_num + 1;
        _search_thread_arg[i].end = (i + 1) * avg_num;
        if_search[i] = true;
    }

    _search_thread_arg[_num_t - 1].start = (_num_t - 1) * avg_num + 1;
    _search_thread_arg[_num_t - 1].end = cnt_upd;
    if_search[_num_t - 1] = true;

    //auto end = chrono::steady_clock::now();
    //chrono::duration<double, std::micro> elapsed = end - start;
    //cout << "lock cleaning thread cost: " << elapsed.count() << endl;


    //start = chrono::steady_clock::now();
    for (unsigned int i = 0; i < _num_t; i++)
        pthread_mutex_unlock(&(mutex_search[i]));
    usleep(50);
    for (unsigned int i = 0; i < _num_t; i++)
        pthread_mutex_lock(&(mutex_search[i]));
    //end = chrono::steady_clock::now();
    //elapsed = end - start;
    //cout << "all threads time cost: " << elapsed.count() << endl;

    //start = chrono::steady_clock::now();
    if_cleaning = true;
    pthread_mutex_unlock(&mutex_CDB);

    for (auto &itr:D)
    {
        for (unsigned int i = 0; i < _num_t; i++)
        {
            if (_search_thread_arg[i].T.find(itr.first) != _search_thread_arg[i].T.end())
            {
                if (_search_thread_arg[i].T[itr.first].i < itr.second)
                    _search_thread_arg[i].T.erase(itr.first);
            }
        }
    }
    for (unsigned int i = 0; i < _num_t; i++)
    {
        for (auto &it : _search_thread_arg[i].T)
        {
            string _l;
            unsigned char buf[80];

            memcpy(buf, it.second.IV, 16);
            memcpy(buf + 16, it.second.C, 64);

            _l.assign((char *) buf, 80);

            ret.emplace_back(_l);
        }


    }
    //end = chrono::steady_clock::now();
    //elapsed = end - start;
    //cout << "collecting data: " << elapsed.count() << endl;
    return 0;
}

void *BestieServer::_do_search_in_cdb(void *data)
{
    BestieServer *_this = ((ThreadInit *) data)->_this;
    unsigned int _num_t = ((ThreadInit *) data)->index;
    unsigned char H_rslt[36], buf[64];
    unordered_map<string, unsigned int> _D;
    unsigned int counter = 0;
    ThreadData *arg = &(_this->_search_thread_arg[_num_t]);

    while (true)
    {
        pthread_mutex_lock(&(_this->mutex_search[_num_t]));
        if (_this->if_thread_exit)
        {
            pthread_mutex_unlock(&(_this->mutex_search[_num_t]));
            delete (ThreadInit *) data;
            usleep(20);
            return nullptr;
        }
        if (_this->if_search[_num_t] == false)
        {
            pthread_mutex_unlock(&(_this->mutex_search[_num_t]));
            usleep(30);
            continue;
        }
        //auto start = chrono::steady_clock::now();
        _this->if_search[_num_t] = false;
        arg->L.clear();
        arg->T.clear();
        _D.clear();

        for (unsigned int i = arg->end; i >= arg->start; i--)
        {
            string _l;
            _hash_H(arg->K, i, buf);
            _l.assign((char *) buf, 32);

            auto *p_c = _this->cipher_db[_l];
            arg->L.emplace_back(_l);
            for (int j = 0; j < 32; j++)
                H_rslt[j] = p_c->D[j] ^ buf[j + 32];

            if (H_rslt[0] == 0xff) //add
            {
                string _x;
                string _c;
                ReturnedCipher _r;
                //memcpy(_c->X, H_rslt + 1, 31);
                _r.i = i;
                memcpy(_r.C, p_c->C, 64);
                memcpy(_r.IV, p_c->IV, 16);
                _x.assign((char *) H_rslt + 1, 31);
                //memcpy(_c->C, p_c->C, 64);
                arg->T[_x] = _r;
            }
            else if (H_rslt[0] == 0) //del
            {
                string _l;
                _l.assign((char *) H_rslt + 1, 31);
                if (_D.find(_l) == _D.end())
                    _D[_l] = i;
            }
            else
            {
                cout << "search process error, data damaged" << endl;
            }
            counter++;
        }
        int flag = 1;
        bool if_D = true;

        while (flag > 0)
        {
            if (if_D)
            {
                pthread_mutex_lock(&(_this->mutex_D));
                for (auto &itr: _D)
                    (*arg->D)[itr.first] = itr.second;
                if_D = false;
                flag--;
                pthread_mutex_unlock(&(_this->mutex_D));
            }
        }
        //auto end = chrono::steady_clock::now();
        //chrono::duration<double, std::micro> elapsed = end - start;
        //cout << "thread " << (unsigned int)pthread_self() << " cost " << elapsed.count() << endl;
        pthread_mutex_unlock(&(_this->mutex_search[_num_t]));
        usleep(30);
    }
}

void *BestieServer::_do_clean_cdb(void *data)
{
    BestieServer *_this = ((ThreadInit *) data)->_this;

    while (true)
    {
        pthread_mutex_lock(&(_this->mutex_CDB));
        if (_this->if_thread_exit)
        {
            pthread_mutex_unlock(&(_this->mutex_CDB));
            delete (ThreadInit *) data;
            usleep(20);
            return nullptr;
        }
        if (_this->if_cleaning == false)
        {
            pthread_mutex_unlock(&(_this->mutex_CDB));
            usleep(40);
            continue;
        }
        _this->if_cleaning = false;
        for (unsigned int i = 0; i < _this->_num_t; i++)
        {
            for (auto &itr:_this->_search_thread_arg[i].L)
            {
                delete _this->cipher_db[itr];
                _this->cipher_db.erase(itr);
            }
        }
        pthread_mutex_unlock(&(_this->mutex_CDB));
        usleep(30);
    }
}

BestieServer::BestieServer()
{
    if_cleaning = false;
    if_thread_exit = false;
    ThreadInit *_ti;

    pthread_mutex_init(&mutex_CDB, nullptr);
    pthread_mutex_init(&mutex_D, nullptr);
    for (int i = 0; i < 64; i++)
        pthread_mutex_init(&(mutex_search[i]), nullptr);

    _ti = new ThreadInit();
    _ti->_this = this;

    if (0 != pthread_create(&p_clean_thread, nullptr, &_do_clean_cdb, _ti))
        cout << "clean thread created failed " << endl;

    for (int i = 0; i < 64; i++)
    {
        _ti = new ThreadInit();
        pthread_mutex_lock(&(mutex_search[i]));
        _ti->_this = this;
        _ti->index = i;
        if_search[i] = false;
        _search_thread_arg[i].L.reserve(200000);
        _search_thread_arg[i].T.reserve(200000);
        if (0 != pthread_create(&(p_search_thread[i]), nullptr, &_do_search_in_cdb, _ti))
            cout << "search thread " << i << "created failed " << endl;
    }
}

BestieServer::~BestieServer()
{
    if_thread_exit = true;
    if_cleaning = false;
    pthread_mutex_unlock(&mutex_CDB);

    for (int i = 0; i < 64; i++)
        pthread_mutex_unlock(&(mutex_search[i]));

    pthread_join(p_clean_thread, nullptr);
    for (int i = 0; i < 64; i++)
        pthread_join(p_search_thread[i], nullptr);

    pthread_mutex_destroy(&mutex_CDB);
    for (int i = 0; i < 64; i++)
        pthread_mutex_destroy(&(mutex_search[i]));

    for (auto &a:this->cipher_db)
        delete a.second;
    this->cipher_db.clear();
    this->GRP.clear();
}
