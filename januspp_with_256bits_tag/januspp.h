//
// Created by Xu Peng on 2019/8/16.
//

#ifndef JANUSPP_JANUSPP_H
#define JANUSPP_JANUSPP_H

#include <vector>
#include <string>
#include <unordered_map>
#include "pun_encryption.h"
#include "diana.h"

const int MAX_DELETESUPPORT = 2000;

class JanusPPClient
{
public:
    JanusPPClient()= default;
    ~JanusPPClient();
    int Setup();
    int Add(const std::string& keyword, unsigned char *label, const std::string& ind, unsigned char *IV, unsigned char *ct, PunTag &tag);
    int Delete(const std::string& keyword, unsigned char *label, const std::string& ind, PuncturedKey *psk, PunTag &tag);
    int trapdoor(const std::string& keyword, unsigned char *msk_out,
                 ConstrainedKey *trpd, unsigned char *kw1, ConstrainedKey *trpd_del, unsigned char *kw1_del);
    PunTag generate_tag(const std::string& keyword, const std::string& ind);

    void dump_data(const std::string &filename="januspp_clnt_data");
    void load_data(const std::string &filename="januspp_clnt_data");

private:
    unsigned char kt[16];
    unsigned char ks[16];
    std::unordered_map<std::string, int> sc;
    std::unordered_map<std::string, int> del;
    std::unordered_map<std::string, unsigned char*> msk;
    std::unordered_map<std::string, unsigned char*> psk;
    int deleting_support;
    DianaClient diana_clnt;
    DianaClient diana_clnt_del;

    int _init_keyword_state(const std::string &keyword);
    int _prf_f(const std::string& keyword, const std::string& ind, unsigned char *data);
};


class JanusPPServer
{
public:
    JanusPPServer()= default;
    ~JanusPPServer()= default;
    int Setup();
    int SaveCipher(unsigned char *label, unsigned char *IV, unsigned char *ct, PunTag &tag);
    int DeleteCipher(unsigned char *label, PuncturedKey *psk, PunTag &tag);
    //Just one time search
    int Search(ConstrainedKey& key, unsigned char *kw1, ConstrainedKey& key_del, unsigned char *kw1_del,
            unsigned char *msk, int d, std::vector<std::string>& output);

    void dump_data(const std::string &filename="januspp_srv_data");
    void load_data(const std::string &filename="januspp_srv_data");

private:
    DianaServer diana_srv;
    DianaServer diana_srv_del;

};


#endif //JANUSPP_JANUSPP_H
