//
// Created by spiraldox on 8/26/19.
//

#ifndef MITRA_MITRA_H
#define MITRA_MITRA_H

#include <vector>
#include <string>
#include <unordered_map>

enum MitraStarOp
{
    Mitra_Add,
    Mitra_Del
};

class MitraStarClient
{
public:
    MitraStarClient() = default;

    ~MitraStarClient() = default;

    int Setup();

    int update(const std::string &keyword, const std::string &ind, MitraStarOp op,
               unsigned char *label, unsigned char *ciphertext);

    int update(const std::string &keyword, std::vector<std::string> &ids,
               std::vector<std::string> &labels, std::vector<std::string> &ciphers);

    int search_stage1(const std::string &keyword, std::vector<std::string> &tlist);

    int search_stage2(const std::string& keyword, std::vector<std::string> &Fw,
            std::vector<std::string> &search_ret, std::vector<std::string> &labels, std::vector<std::string> &ciphers);

    void dump_data(const std::string &filename="mitra_star_clnt_data");
    void load_data(const std::string &filename="mitra_star_clnt_data");

private:
    unsigned char k_master[16];
    std::unordered_map<std::string, unsigned int> FileCnt;
    std::unordered_map<std::string, unsigned int> SrcCnt;
    int _prf_gen_label(unsigned char *srckey, const std::string &keyword, unsigned int c, unsigned char *label);
    int _prf_gen_ciphertext(unsigned char * srckey, const std::string &keyword, unsigned int c, unsigned char *ciphertext);
    int _prf_gen_srckey(unsigned int c, unsigned char *srckey);
};

class MitraStarServer
{
public:
    MitraStarServer() = default;

    ~MitraStarServer() = default;

    int Setup();

    int save(unsigned char *label, unsigned char *cipher);
    int save(const std::vector<std::string> &labels, const std::vector<std::string> &ciphers);

    int search(std::vector<std::string> &tlist, std::vector<std::string> &Fw);



    void dump_data(const std::string &filename="mitra_srv_data");
    void load_data(const std::string &filename="mitra_srv_data");
    std::unordered_map<std::string, std::string> cipher_db;
};


#endif //MITRA_MITRA_H
