//
// Created by Xu Peng on 2019/8/15.
//

#ifndef JANUSPP_DIANA_H
#define JANUSPP_DIANA_H

#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include "constrained_prf.h"

struct DianaData
{
    unsigned char ct[64];
    int len;
};

class DianaClient
{
    public:
    DianaClient()= default;
    ~DianaClient()= default;
    int Setup();
    int update(const std::string& keyword, unsigned char *output, unsigned int& c, unsigned char *bytes_to_enc_id,
               unsigned char *Kw);
    int trapdoor(const std::string& keyword, ConstrainedKey& trpdr_key, unsigned char *kw1_out);
    unsigned int get_keyword_counter(const std::string &keyword);
    int get_kw_and_kw1(const std::string& keyword, unsigned char *kw_out, unsigned char *kw1_out);

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);
private:
    unsigned char key_master[16];
    std::map<std::string, unsigned int> keywords_conuter;
    int _prf_F(const unsigned char *in, unsigned long len, unsigned char *out);

};

class DianaServer
{
public:
    DianaServer()
    {
        cipher_store.clear();
    }
    ~DianaServer();
    int Setup();
    int Save(unsigned char *label, unsigned char *data, int length=64);
    int Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData*>& out);
    int SearchRange(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData*>& out);

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);
private:
    std::unordered_map<std::string, DianaData*> cipher_store;
};

int print_hex(unsigned char *data, int len);

#endif //JANUSPP_DIANA_H
