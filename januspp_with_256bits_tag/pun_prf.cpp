//
// Created by Xu Peng on 2019/9/4.
//

#include <iostream>
#include <cstring>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
}

#include "pun_prf.h"


using std::cout;
using std::endl;

PunTag::PunTag(unsigned long long data)
{
    memset(this->tag_data + 1, 0, 24);
    this->tag_data[0] = data;
    this->tag_data_ptr = (unsigned char *) this->tag_data;
}

PunTag::PunTag(const PunTag &_tag)
{
    memcpy(this->tag_data, _tag.tag_data, 32);
    this->tag_data_ptr = (unsigned char *) this->tag_data;
}

int PunTag::set_data(unsigned long long value)
{
    memset(this->tag_data + 1, 0, 24);
    this->tag_data[0] = value;
    return 1;
}

PunTag &PunTag::operator=(const PunTag &_tag)
{
    if(&_tag != this)
        memcpy(this->tag_data, _tag.tag_data, 32);

    return *this;
}

PunTag PunTag::operator|(const PunTag &_tag)
{
    PunTag _t(*this);

    for (int i = 0; i < 4; i++)
        _t.tag_data[i] = _t.tag_data[i] | _tag.tag_data[i];

    return _t;
}

PunTag PunTag::operator^(const PunTag &_tag)
{
    PunTag _t(*this);

    for (int i = 0; i < 4; i++)
        _t.tag_data[i] = _t.tag_data[i] ^ _tag.tag_data[i];

    return _t;
}

PunTag PunTag::operator&(const PunTag &_tag)
{
    PunTag _t(*this);

    for (int i = 0; i < 4; i++)
        _t.tag_data[i] = _t.tag_data[i] & _tag.tag_data[i];

    return _t;
}

PunTag PunTag::operator<<(unsigned int bits)
{
    PunTag _t(*this);

    unsigned long long hmask = 1u << 31u;
    bool of = false;
    bool of_new;

    hmask <<= 32u;

    for (unsigned int _i = 0; _i < bits; _i++)
    {
        of = false;
        for (unsigned long long &_data : _t.tag_data)
        {
            of_new = (hmask & _data) != 0;
            _data <<= 1u;
            if (of)
                _data |= 1u;
            of = of_new;
        }
    }

    return _t;
}

PunTag PunTag::operator>>(unsigned int bits)
{
    PunTag _t(*this);

    unsigned long long lmask = 1u;
    unsigned long long hmask = 1u << 31u;
    bool of = false;
    bool of_new;

    hmask <<= 32u;

    for (unsigned int _i = 0; _i < bits; _i++)
    {
        of = false;
        for (int i = 3; i >= 0; i--)
        {
            unsigned long long &_data = _t.tag_data[i];

            of_new = (lmask & _data) != 0;
            _data >>= 1u;
            if (of)
                _data |= hmask;
            of = of_new;
        }
    }

    return _t;
}

bool PunTag::is_0()
{
    bool flag = true;

    for (unsigned long long &_data : this->tag_data)
        if (_data != 0)
        {
            flag = false;
            break;
        }

    return flag;
}

unsigned char &PunTag::operator[](int index)
{
    if ((index > 31) || (index < 0))
    {
        cout << "warning, index of PunTag is out of range, returned the first byte" << endl;
        return this->tag_data_ptr[0];
    }

    return this->tag_data_ptr[index];
}

PunTag &PunTag::operator<<=(unsigned int bits)
{
    unsigned long long hmask = 1u << 31u;
    bool of = false;
    bool of_new;

    hmask <<= 32u;

    for (unsigned int _i = 0; _i < bits; _i++)
    {
        of = false;
        for (unsigned long long &_data : this->tag_data)
        {
            of_new = (hmask & _data) != 0;
            _data <<= 1u;
            if (of)
                _data |= 1u;
            of = of_new;
        }
    }
    return *this;
}

PunTag &PunTag::operator>>=(unsigned int bits)
{
    unsigned long long lmask = 1u;
    unsigned long long hmask = 1u << 31u;
    bool of = false;
    bool of_new;

    hmask <<= 32u;

    for (unsigned int _i = 0; _i < bits; _i++)
    {
        of = false;
        for (int i = 3; i >= 0; i--)
        {
            unsigned long long &_data = this->tag_data[i];

            of_new = (lmask & _data) != 0;
            _data >>= 1u;
            if (of)
                _data |= hmask;
            of = of_new;
        }
    }

    return *this;
}

bool PunTag::operator==(const PunTag &_tag)
{
    return memcmp(this->tag_data_ptr, _tag.tag_data_ptr, 32) == 0;
}

PunTag PunTag::operator~()
{
    for(int i=0; i<4; i++)
        this->tag_data[i]  = ~this->tag_data[i];

    return *this;
}

void PunTag::dump_data(FILE *f_out)
{
    for(int i=0; i<4; i++)
        fwrite(&(this->tag_data[i]), sizeof(char), sizeof(unsigned long long), f_out);

}

void PunTag::load_data(FILE *f_in)
{
    for(int i=0; i<4; i++)
        fread(&(this->tag_data[i]), sizeof(char), sizeof(unsigned long long), f_in);
}

PuncturedKey::PuncturedKey(unsigned char *data)
{
    this->type = NORMAL;

    auto *_data = new unsigned char[16];
    memcpy(_data, data, 16);
    this->keydata.emplace_back(_data);
}

PuncturedKey::~PuncturedKey()
{
    for (auto itr : this->keydata)
    {
        delete[] itr;
    }
}

PuncturedKey::PuncturedKey(const PuncturedKey &k)
{
    if (&k == this)
        return;
    this->type = k.type;
    for (auto itr:this->keydata)
        delete[] itr;
    this->keydata.clear();
    this->tag_prefix.clear();

    for (auto itr:k.keydata)
    {
        auto data = new unsigned char[16];
        memcpy(data, itr, 16);
        this->keydata.emplace_back(data);
    }

    for (auto &itr:k.tag_prefix)
    {
        this->tag_prefix.emplace_back(itr);
    }
}

PuncturedKey &PuncturedKey::operator=(const PuncturedKey &k)
{
    if (this == &k)
        return *this;
    this->type = k.type;
    for (auto itr:this->keydata)
        delete[] itr;
    this->keydata.clear();
    this->tag_prefix.clear();

    for (auto itr:k.keydata)
    {
        auto data = new unsigned char[16];
        memcpy(data, itr, 16);
        this->keydata.emplace_back(data);
    }

    for (auto &itr:k.tag_prefix)
    {
        this->tag_prefix.emplace_back(itr);
    }
    return *this;
}

size_t PuncturedKey::size()
{
    size_t ret = 0;

    ret = 16 * this->keydata.size();
    ret += 2 * ((4 * sizeof(unsigned int)) * this->tag_prefix.size());

    return ret;
}

int PuncturedKey::hash(unsigned char *hash_out)
{
    unsigned char buf1[64], buf2[32];
    if (this->keydata.empty())
    {
        memset(hash_out, 0, 32);
        return 0;
    }
    SHA256(this->keydata[0], 16, buf1);
    for (size_t i = 1; i < this->keydata.size(); i++)
    {
        memcpy(buf1 + 32, this->keydata[i], 16);
        SHA256(buf1, 48, buf2);
        memcpy(buf1, buf2, 32);
    }
    memcpy(hash_out, buf1, 32);
    return 1;
}

void PuncturedKey::dump_data(FILE *f_out)
{
    unsigned long len_vec = this->keydata.size();

    fwrite(&type, sizeof(char), sizeof(type), f_out);
    fwrite(&len_vec, sizeof(char), sizeof(len_vec), f_out);

    for (unsigned char *itr:this->keydata)
        fwrite(itr, sizeof(char), 16, f_out);

    len_vec = this->tag_prefix.size();

    fwrite(&len_vec, sizeof(char), sizeof(len_vec), f_out);

    for (auto &itr:this->tag_prefix)
    {
        itr.mask.dump_data(f_out);
        itr.path_data.dump_data(f_out);
    }
}

void PuncturedKey::load_data(FILE *f_in)
{
    unsigned long len_vec;

    for (auto &itr:this->keydata)
        delete[] itr;

    this->keydata.clear();
    this->tag_prefix.clear();

    fread(&type, sizeof(char), sizeof(type), f_in);
    fread(&len_vec, sizeof(char), sizeof(len_vec), f_in);

    for (unsigned long i = 0; i < len_vec; i++)
    {
        auto data = new unsigned char[16];
        fread(data, sizeof(char), 16, f_in);
        this->keydata.emplace_back(data);
    }

    fread(&len_vec, sizeof(char), sizeof(len_vec), f_in);

    for (unsigned long i = 0; i < len_vec; i++)
    {
        PunTag mask, path_data;

        mask.load_data(f_in);
        path_data.load_data(f_in);
        this->tag_prefix.emplace_back(Path{path_data, mask});
    }
}

PuncturablePRF::PuncturablePRF()
{
    for (int i = 0; i < 16; i++)
    {
        if (i % 2 == 1)
        {
            _data_0[i] = 1;
            _data_1[i] = 0;
        }
        else
        {
            _data_0[i] = 0;
            _data_1[i] = 1;
        }
    }
}

int PuncturablePRF::Eval(PuncturedKey &key, PunTag &tag, unsigned char *out_result)
{
    if (key.type == NORMAL)
    {
        this->Eval(key.keydata[0], tag, out_result);
        return 1;
    }
    else
    {
        for (int i = 0; i < (int) key.tag_prefix.size(); i++)
        {
            if ((key.tag_prefix[i].mask & key.tag_prefix[i].path_data) == (key.tag_prefix[i].mask & tag))
            {
                this->_Eval_from_path(key.keydata[i], tag, i + 1, out_result);
                return 1;
            }
        }
        return 0;
    }
}

int PuncturablePRF::Eval(unsigned char *key, PunTag &tag, unsigned char *out_result)
{
    this->_Eval_from_path(key, tag, 0, out_result);

    return 1;
}

int PuncturablePRF::_Eval_from_path(unsigned char *key, PunTag &tag, int level, unsigned char *out_result)
{
    unsigned char iv[16];
    unsigned char tmp1[64], tmp2[64];
    PunTag mask(1u), mask_inv(1u);
    AES_KEY aes_key;

    mask <<= 255u;
    mask_inv <<= 255u;
    mask_inv = ~mask_inv;

    for (int i = 0; i < level; i++)
        mask = (mask >> 1u) & mask_inv;

    memcpy(tmp1, key, 16);
    memcpy(tmp2, key, 16);

    for (int i = level; i < 256; i++)
    {
        unsigned char *data_to_enc;

        if ((mask & tag).is_0())
            data_to_enc = _data_0;
        else
            data_to_enc = _data_1;

        memset(iv, 0, 16);

        if (i % 2 == 0)
        {
            AES_set_encrypt_key(tmp1, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, tmp2, 16, &aes_key, iv, AES_ENCRYPT);
        }
        else
        {
            AES_set_encrypt_key(tmp2, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, tmp1, 16, &aes_key, iv, AES_ENCRYPT);
        }
        mask = (mask >> 1u) & mask_inv;
    }

    memcpy(out_result, tmp1, 16);

    return 1;
}

int PuncturablePRF::Punc(unsigned char *sk, PunTag &tag, PuncturedKey &out_pun_key)
{
    PunTag first_bit(1u), traveled(0), traveled_mask(0);
    PunTag mask_inv(1u);
    unsigned char iv[16], tmp1[64], tmp2[64];
    AES_KEY aes_key;

    first_bit <<= 255u;
    mask_inv <<= 255u;
    mask_inv = ~mask_inv;

    if (!out_pun_key.keydata.empty())
    {
        for (auto itr : out_pun_key.keydata)
        {
            delete[] itr;
        }
        out_pun_key.keydata.clear();
    }
    if (!out_pun_key.tag_prefix.empty())
        out_pun_key.tag_prefix.clear();

    out_pun_key.type = PUNCTURED;

    for (int i = 0; i < 256; i++)
    {
        unsigned char *data_to_enc;

        out_pun_key.keydata.emplace_back(new unsigned char[16]);

        if (traveled_mask.is_0())
        {
            traveled_mask = first_bit;
            if ((traveled_mask & tag).is_0())
                data_to_enc = _data_1;
            else
                data_to_enc = _data_0;

            memset(iv, 0, 16);
            AES_set_encrypt_key(sk, 128, &aes_key);
            AES_cbc_encrypt(data_to_enc, out_pun_key.keydata[0], 16, &aes_key, iv, AES_ENCRYPT);
            traveled = first_bit;
            out_pun_key.tag_prefix.emplace_back(Path{first_bit ^ (first_bit & tag), traveled});
        }
        else
        {
            //calculate prefix

            PunTag mask_prefix = first_bit;
            PunTag path;

            memcpy(tmp1, sk, 16);
            memcpy(tmp2, sk, 16);

            for (int j = 0; j < i; j++)
            {
                if ((mask_prefix & tag).is_0())
                    data_to_enc = _data_0;
                else
                    data_to_enc = _data_1;

                memset(iv, 0, 16);

                if (j % 2 == 0)
                {
                    AES_set_encrypt_key(tmp1, 128, &aes_key);
                    AES_cbc_encrypt(data_to_enc, tmp2, 16, &aes_key, iv, AES_ENCRYPT);
                }
                else
                {
                    AES_set_encrypt_key(tmp2, 128, &aes_key);
                    AES_cbc_encrypt(data_to_enc, tmp1, 16, &aes_key, iv, AES_ENCRYPT);
                }
                mask_prefix = (mask_prefix >> 1u) & mask_inv;
            }

            if ((mask_prefix & tag).is_0())
                data_to_enc = _data_1;
            else
                data_to_enc = _data_0;

            if (i % 2 == 0)
                AES_set_encrypt_key(tmp1, 128, &aes_key);
            else
                AES_set_encrypt_key(tmp2, 128, &aes_key);

            memset(iv, 0, 16);
            AES_cbc_encrypt(data_to_enc, out_pun_key.keydata[i], 16, &aes_key, iv, AES_ENCRYPT);

            traveled_mask = (traveled_mask >> 1u) & mask_inv;

            traveled = (traveled >> 1u) | first_bit;
            path = tag & traveled;
            path = path ^ traveled_mask;
            out_pun_key.tag_prefix.emplace_back(Path{path, traveled});
        }
    }
    return 1;
}
