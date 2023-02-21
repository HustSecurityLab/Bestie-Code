//
// Created by Xu Peng on 2019/8/20.
//

#ifndef DIANADEL_DIANADEL_H
#define DIANADEL_DIANADEL_H

#include <vector>
#include <string>
#include <list>
#include <unordered_map>
#include "diana.h"

struct CipherRange
{
    unsigned int start;
    unsigned int end;
};

class DianaDelClient
{
public:
    DianaDelClient() = default;

    ~DianaDelClient() = default;

    int Setup();

    int Add(const std::string &keyword, const std::string &ind, unsigned char *label, unsigned char *enc_id,
            unsigned char *F_K_w_ind, unsigned char *IV, unsigned char *Enc_K_counter);

    int Delete(const std::string &keyword, const std::string &ind, unsigned char *label, unsigned char *enc_F_K_w_ind);

    int trapdoor_for_diana_clnt_del(const std::string &keyword, ConstrainedKey *trpd, unsigned char *kw1);

    int trapdoor_for_diana_clnt(const std::string &keyword, std::vector<std::string> &enc_counters_to_del,
                                std::vector<ConstrainedKey *> &range_keys, unsigned char *kw1);

    void dump_data(const std::string &filename = "dianadel_clnt_data");

    void load_data(const std::string &filename = "dianadel_clnt_data");

private:
    DianaClient diana_clnt;
    DianaClient diana_clnt_del;
    unsigned char key_se[16];

    static int _split_counter_range(const std::vector<unsigned int> &counter_to_del, std::list<CipherRange> &range);

    static int _prf_F1(const unsigned char *kw, const std::string &keyword, const std::string &ind, unsigned char *out);
};

class DianaDelServer
{
public:
    DianaDelServer() = default;

    ~DianaDelServer() = default;

    int Setup();

    int Add(unsigned char *label, unsigned char *enc_id, unsigned char *F_k_w_ind, unsigned char *IV,
            unsigned char *Enc_K_counter);

    int Delete(unsigned char *label, unsigned char *enc_F_K_w_ind);

    int SearchStage1(ConstrainedKey *trpd, unsigned char *kw1, std::vector<std::string> &enc_counters_to_del);

    int
    SearchStage2(const std::vector<ConstrainedKey *> &range_keys, unsigned char *kw1, std::vector<std::string> &id_ret);

    void dump_data(const std::string &filename = "dianadel_srv_data");

    void load_data(const std::string &filename = "dianadel_srv_data");

private:
    DianaServer diana_srv;
    DianaServer diana_srv_del;
    std::unordered_map<std::string, std::string> enc_counter;

};

#endif //DIANADEL_DIANADEL_H
