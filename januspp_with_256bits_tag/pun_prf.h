//
// Created by Xu Peng on 2019/9/4.
//

#ifndef JANUSPP_WITH_256BITS_TAG_PUN_PRF_H
#define JANUSPP_WITH_256BITS_TAG_PUN_PRF_H

#include <vector>
#include <cstdio>

enum PuncturedKeyType
{
    NORMAL,
    PUNCTURED
};

class PunTag
{
public:
    explicit PunTag(unsigned long long data = 0);

    PunTag(const PunTag &_tag);

    ~PunTag() = default;

    PunTag &operator=(const PunTag &_tag);

    int set_data(unsigned long long value);

    unsigned char *get_data_ptr()
    { return this->tag_data_ptr; }

    PunTag operator|(const PunTag &_tag);

    PunTag operator^(const PunTag &_tag);

    PunTag operator&(const PunTag &_tag);

    PunTag operator~();

    bool operator==(const PunTag &_tag);

    PunTag operator<<(unsigned int bits);

    PunTag operator>>(unsigned int bits);

    PunTag &operator<<=(unsigned int bits);

    PunTag &operator>>=(unsigned int bits);

    unsigned char &operator[](int index);

    inline size_t size() const
    { return 4 * sizeof(long long); }

    bool is_0();

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);

private:
    //little endian
    unsigned long long tag_data[4];
    unsigned char *tag_data_ptr;
};


struct Path
{
    PunTag path_data;
    PunTag mask;
};

struct PuncturedKey
{
    PuncturedKey() = default;

    explicit PuncturedKey(unsigned char *data);

    PuncturedKey(const PuncturedKey &k);

    PuncturedKey &operator=(const PuncturedKey &k);

    ~PuncturedKey();

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);

    PuncturedKeyType type = NORMAL;
    std::vector<unsigned char *> keydata;
    std::vector<Path> tag_prefix;

    size_t size();

    int hash(unsigned char *hash_out);
};

class PuncturablePRF
{
public:
    PuncturablePRF();

    int Eval(PuncturedKey &key, PunTag &tag, unsigned char *out_result);

    int Eval(unsigned char *key, PunTag &tag, unsigned char *out_result);

    int Punc(unsigned char *sk, PunTag &tag, PuncturedKey &out_pun_key);

private:

    unsigned char _data_0[16], _data_1[16];

    int _Eval_from_path(unsigned char *key, PunTag &tag, int level, unsigned char *out_result);
};


#endif //JANUSPP_WITH_256BITS_TAG_PUN_PRF_H
