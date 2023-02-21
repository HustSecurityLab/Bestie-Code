//
// Created by Xu Peng on 2019/8/15.
//

#ifndef JANUSPP_DIANA_H
#define JANUSPP_DIANA_H

#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include "pun_prf.h"
#include "constrained_prf.h"

struct DianaData
{
    unsigned char ct[64];
    unsigned char IV[16];
    PunTag tag;
};

struct DianaDataDel
{
    PuncturedKey *key;
    PunTag tag;
};

class DianaClient
{
    public:
    DianaClient()= default;
    ~DianaClient()= default;
    int Setup();
    int update(const std::string& keyword, unsigned char *output);
    int trapdoor(const std::string& keyword, ConstrainedKey& trpdr_key, unsigned char *kw1_out);

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);

private:
    unsigned char key_master[16];
    std::map<std::string, unsigned int> keywords_conuter;
    void PRF_F_sha256(const char *keyword, unsigned int len, unsigned char *out);
};

class DianaServer
{
public:
    DianaServer()= default;
    ~DianaServer();
    int Setup();
    int Save(unsigned char *label, unsigned char *IV, unsigned char *cipher, PunTag &tag);
    int Save(unsigned char *label, PuncturedKey *key, PunTag &tag);
    int Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData*>& out);
    int Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaDataDel*>& out);

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);
private:
    std::unordered_map<std::string, DianaData*> cipher_store;
    std::unordered_map<std::string, DianaDataDel*> psk_store;
};

#endif //JANUSPP_DIANA_H
