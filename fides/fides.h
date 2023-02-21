//
// Created by Xu Peng on 2019/8/25.
//

#ifndef FIDES_FIDES_H
#define FIDES_FIDES_H

#include <string>
#include <vector>
#include <unordered_map>
#include "sophos.h"

class FidesClient;

enum FidesOp
{
    Fides_Add,
    Fides_Del
};

struct ParallelDATA
{
    FidesClient *_this;
    std::string *keyword;
    std::vector<std::string> *inds;
    int sno;
};

class FidesClient
{
public:
    FidesClient() = default;

    ~FidesClient() = default;

    int Setup();

    int update(const std::string &keyword, const std::string &ind, FidesOp op, unsigned char *label,
               unsigned char *IV, unsigned char *ciphertext);

    int search_stage1(const std::string &keyword, unsigned char *kw, unsigned char *st, unsigned int &counter);

    int search_stage2(const std::string &keyword, std::vector<std::string> &enc_data, std::vector<std::string> &out);

    int get_pk(TdpPK *pk);

    int update_after_search(const std::string &keyword, std::vector<std::string> &inds,
                            std::vector<std::string> &vec_label, std::vector<std::string> &vec_cipher);

    void dump_data(const std::string &filename = "fides_clnt_data");

    void load_data(const std::string &filename = "fides_clnt_data");

private:
    std::unordered_map<std::string, unsigned int> Tw;
    unsigned char K_master[16];
    SophosClient sophos_clnt;

    int _gen_kw(const std::string &keyword, unsigned char *Kw);
};

class FidesServer
{
public:
    FidesServer() = default;

    ~FidesServer() = default;

    int Setup();

    int save(unsigned char *label, unsigned char *IV, unsigned char *value);

    int save(std::vector<std::string> &labels, std::vector<std::string> &ciphers);

    int search(TdpPK *pk, unsigned char *kw, unsigned char *st, unsigned int counter,
               std::vector<std::string> &out);

    void dump_data(const std::string &filename = "fides_srv_data");

    void load_data(const std::string &filename = "fides_srv_data");

private:
    SophosServer sophos_srv;
};


#endif //FIDES_FIDES_H
