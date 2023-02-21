//
// Created by Xu Peng on 2019/8/14.
//

#ifndef JANUSPP_CONSTRAINED_PRF_H
#define JANUSPP_CONSTRAINED_PRF_H

#include <cstdio>
#include <vector>

struct PathData
{
    unsigned int path;
    unsigned int level;
    unsigned int mask;
};

struct ConstrainedKeyData
{
    unsigned char key_data[16];
    unsigned int level;
    unsigned int path;
};

struct ConstrainedKey
{
    ~ConstrainedKey();

    size_t size();

    int hash(unsigned char *out);

    unsigned int current_permitted;
    unsigned int max_permitted;
    std::vector<ConstrainedKeyData *> permitted_keys;
    unsigned int start, end;
    int write_to_file(FILE *f_out);
    int read_from_file(FILE *f_in);
};

class ConstrainedPRF
{
public:
    ConstrainedPRF();

    int Eval(unsigned char *K, unsigned int per_num, unsigned char *out);

    int Eval(ConstrainedKey& key, unsigned int counter, unsigned char *out);

    int Eval_range(ConstrainedKey& key, unsigned int counter, unsigned char *out);

    int Constrain(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

    int Constrain(const unsigned char *K, unsigned int start, unsigned int end, ConstrainedKey &out);

private:
    int _Eval_from_path(unsigned char *key, unsigned int tag, unsigned int level, unsigned char *out_result);

    //for numbers from 0 to per_num-1;
    int _Constrain_internal_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

    int _Constrain_last_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

    static int _Constrain_between_nodes(unsigned int start, unsigned int end, unsigned int level, std::vector<PathData> &out);

    unsigned char _data_0[16], _data_1[16];
};

int print_hex(unsigned char *data, int len=16);


#endif //JANUSPP_CONSTRAINED_PRF_H
