//
// Created by spiraldox on 8/27/19.
//

#ifndef ROSEPP_BESTIE_H
#define ROSEPP_BESTIE_H

#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <string>
//#include <mutex>

extern "C"
{
#include <pthread.h>
};

enum BestieOp
{
    Bestie_Add,
    Bestie_Del
};

struct BestieCounter
{
    unsigned int cnt_upd;
    unsigned int cnt_srch;
};

struct ReturnedCipher
{
    unsigned char IV[16];
    unsigned char C[64];
    int i;
};

struct BestieCipher
{
    unsigned char D[32];
    unsigned char IV[16];
    unsigned char C[64];
};

class BestieClient
{
public:
    BestieClient() = default;

    ~BestieClient() = default;

    int Setup();

    int update(const std::string &keyword, const std::string &ind, BestieOp op,
               unsigned char *L, unsigned char *D, unsigned char *IV, unsigned char *C);

    int trapdoor(const std::string &keyword, unsigned int &cnt_upd, unsigned char *K,
                 unsigned char *loc_grp);

    int decrypt(std::vector<std::string> &enc_ind, std::vector<std::string> &result);
    int decrypt(std::unordered_map<std::string, ReturnedCipher> &enc_ind, std::vector<std::string> &result);
    void dump_data(const std::string &filename="bestie_clnt_dumped");
    void load_data(const std::string &filename="bestie_clnt_dumped");

private:
    std::unordered_map<std::string, BestieCounter> count;
    unsigned char k_aes[16];
    unsigned char s[16];

    int _prf_F(const std::string &keyword, unsigned int c, unsigned char *out, bool is_1 = false);

    static int _hash_G(unsigned char *K, const std::string& keyword, const std::string& ind, unsigned char *out);

    int _encrypt_id(const std::string& ind, unsigned char *IV, unsigned char *c);

    static int _hash_H(unsigned char *K, unsigned int c, unsigned char *out);
};

class BestieServer
{
public:
    BestieServer();
    ~BestieServer();
    int Setup();
    int save(unsigned char *label, unsigned char *D, unsigned char *IV, unsigned char *C);
    int search(unsigned int cnt_upd, unsigned char *K, unsigned char *loc_grp, std::vector<std::string>& ret);
    int search_in_parallel(unsigned int cnt_upd, unsigned char *K, unsigned char *loc_grp,
                           std::vector<std::string>& ret, int num_thread);

    void dump_data(const std::string &filename="bestie_srv_dumped");
    void load_data(const std::string &filename="bestie_srv_dumped");
private:
    struct _Label
    {
        std::string l;
        unsigned char mask[32];
    };

    struct ThreadData
    {
        BestieServer* _this;
        unsigned int start;
        unsigned int end;
        unsigned char *K;
        std::unordered_map<std::string, ReturnedCipher> T;
        std::unordered_map<std::string, unsigned int> *D;
        std::vector<std::string> L;
    };

    struct ThreadInit
    {
        BestieServer *_this;
        unsigned int index;
    };

    std::unordered_map<std::string, BestieCipher*> cipher_db;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> GRP;

    static int _hash_H(unsigned char *K, unsigned int c, unsigned char *out);

    static void *_do_search_in_cdb(void *data);
    static void *_do_clean_cdb(void *data);

    pthread_t p_clean_thread;
    volatile bool if_cleaning;
    pthread_t p_search_thread[64];
    volatile bool if_thread_exit;
    volatile bool if_search[64];
    //std::mutex mutex_search[64], mutex_CDB, mutex_D;
    pthread_mutex_t mutex_search[64], mutex_CDB, mutex_D;
    unsigned int _num_t;
    std::unordered_map<std::string, unsigned int> *_D;
    ThreadData _search_thread_arg[64];
};


#endif //ROSEPP_BESTIE_H
