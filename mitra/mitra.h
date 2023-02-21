//
// Created by spiraldox on 8/26/19.
//

#ifndef MITRA_MITRA_H
#define MITRA_MITRA_H

#include <vector>
#include <string>
#include <unordered_map>

enum MitraOp
{
    Mitra_Add,
    Mitra_Del
};

class MitraClient
{
public:
    MitraClient() = default;

    ~MitraClient() = default;

    int Setup();

    int update(const std::string &keyword, const std::string &ind, MitraOp op,
               unsigned char *label, unsigned char *ciphertext);

    int search_stage1(const std::string &keyword, std::vector<std::string> &tlist);

    int search_stage2(const std::string& keyword, std::vector<std::string> &Fw,
            std::vector<std::string> &search_ret);

    void dump_data(const std::string &filename="mitra_clnt_data");
    void load_data(const std::string &filename="mitra_clnt_data");

private:
    unsigned char k_master[16];
    std::unordered_map<std::string, unsigned int> FileCnt;
    int _prf_gen_label(const std::string &keyword, unsigned int c, unsigned char *label);
    int _prf_gen_ciphertext(const std::string &keyword, unsigned int c, unsigned char *ciphertext);
};

class MitraServer
{
public:
    MitraServer() = default;

    ~MitraServer() = default;

    int Setup();

    int save(unsigned char *label, unsigned char *cipher);

    int search(std::vector<std::string> &tlist, std::vector<std::string> &Fw);

    void dump_data(const std::string &filename="mitra_srv_data");
    void load_data(const std::string &filename="mitra_srv_data");

private:
    std::unordered_map<std::string, std::string> cipher_db;
};


#endif //MITRA_MITRA_H
