//
// Created by spiraldox on 9/2/19.
//

#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "dianadel.h"

extern "C"
{
#include <openssl/rand.h>
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    char name[256], word[256];
    FILE *f_data = fopen(filename.c_str(), "r");
    unsigned char label[32], enc_id[80], F_k_w_ind[64], enc_counter[64], IV[64], kw1[64];
    DianaDelClient diana_del_clnt;
    DianaDelServer diana_del_srv;
    FILE *fp_clnt = fopen("dianadel_clnt_data", "rb");
    FILE *fp_srv = fopen("dianadel_srv_data", "rb");

    this->total_add_records = 0;
    fscanf(f_data, "%d\n", &this->keyword_number);
    for (int i = 0; i < this->keyword_number; i++)
    {
        fscanf(f_data, "%s\n", word);
        if (this->data_to_encrypt.find(word) == this->data_to_encrypt.end())
        {
            vector<string> _t;
            this->data_to_encrypt[word] = _t;
        }

        vector<string> &_v = this->data_to_encrypt[word];

        int file_numbers = 0;
        fscanf(f_data, "%d\n", &file_numbers);
        for (int j = 0; j < file_numbers; j++)
        {
            this->total_add_records += 1;
            fscanf(f_data, "%s\n", name);
            _v.emplace_back(string(name));
        }
    }
    fclose(f_data);

    cout << "read " << this->total_add_records << " add records " << endl << endl;

    if (fp_clnt && fp_srv)
    {
        fclose(fp_clnt);
        fclose(fp_srv);
    }
    else
    {
        diana_del_clnt.Setup();
        diana_del_srv.Setup();
        for (const auto &a:data_to_encrypt)
        {
            for (const auto &f_name:a.second)
            {
                diana_del_clnt.Add(a.first, f_name, label, enc_id, F_k_w_ind, IV, enc_counter);
                diana_del_srv.Add(label, enc_id, F_k_w_ind, IV, enc_counter);
            }
        }
        diana_del_clnt.dump_data("dianadel_clnt_data");
        diana_del_srv.dump_data("dianadel_srv_data");
    }


/*
    ConstrainedKey key;
    vector<ConstrainedKey *> range_keys;
    vector<string> plain_out, enc_counters;

    diana_del_clnt.trapdoor_for_diana_clnt_del("2001", &key, kw1);

    diana_del_srv.SearchStage1(&key, kw1, enc_counters);
    diana_del_clnt.trapdoor_for_diana_clnt("2001", enc_counters, range_keys, kw1);
    diana_del_srv.SearchStage2(range_keys, kw1, plain_out);

    cout << "searched: " << plain_out.size() << endl;
    cout << "the first id: " << plain_out[0] << endl;*/

    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    DianaDelClient diana_del_clnt;
    unsigned char label[32], cipher[80], enc_counter[64], enc_F_k_w_ind[64], IV[16];
    int _add_number = 0;

    diana_del_clnt.Setup();

    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            diana_del_clnt.Add(a.first, f_name, label, cipher, enc_F_k_w_ind, IV, enc_counter);
            _add_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "encryption time cost: " << endl;
    cout << "\ttotally " << _add_number << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / _add_number << " us" << endl;
    cout << "length of a ciphertext is " << 32 + 64 + 32 + 16 + 16 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    DianaDelClient diana_del_clnt;
    unsigned char label[32], cipher[80], enc_counter[64], F_k_w_ind[64], enc_F_k_w_ind[64], IV[16];
    int _del_number = 0;

    diana_del_clnt.Setup();
    diana_del_clnt.load_data("dianadel_clnt_data");

    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            diana_del_clnt.Delete(a.first, f_name, label, enc_F_k_w_ind);
            _del_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number << " us" << endl << endl;
    cout << "length of a deleting ciphertext is " << 32 + 32 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    DianaDelClient diana_del_clnt;
    DianaDelServer diana_del_srv;
    unsigned char label[32], enc_id[80], enc_counter[64], F_k_w_ind[64], kw1[64];
    ConstrainedKey key;
    vector<ConstrainedKey *> range_keys;
    vector<string> plain_out, enc_counters;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;

    //set up the client and the server and load data
    diana_del_clnt.Setup();
    diana_del_srv.Setup();

    diana_del_clnt.load_data("dianadel_clnt_data");
    diana_del_srv.load_data("dianadel_srv_data");

    //for every keywords, execute search
    for (auto &itr: this->data_to_encrypt)
    {

        plain_out.clear();
        enc_counters.clear();
        for(ConstrainedKey * ckey : range_keys)
            delete ckey;
        range_keys.clear();

        plain_out.reserve(300000);
        enc_counters.reserve(300000);
        range_keys.reserve(300000);

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        diana_del_clnt.trapdoor_for_diana_clnt_del(itr.first, &key, kw1);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = key.size() + 16; // kw1 is 16 Bytes


        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        diana_del_srv.SearchStage1(&key, kw1,enc_counters);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += enc_counters.size() * 32;

        //search stage 3: generat GGM trapdoor
        start = std::chrono::steady_clock::now();
        diana_del_clnt.trapdoor_for_diana_clnt(itr.first, enc_counters, range_keys, kw1);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        for(auto &it : range_keys)
        {
            total_data_size += it->size();
        }
        total_data_size += 16;

        //search stage 4: save re-encrypted cipehrtexts
        start = std::chrono::steady_clock::now();
        diana_del_srv.SearchStage2(range_keys, kw1, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch += elapsed.count();

        total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

        cout << "Searching for keyword: " << itr.first << endl;
        cout << "\tTotally find " << plain_out.size() << " records and the last file ID is "
             << plain_out[plain_out.size() - 1] << endl;
        cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
             << clnt_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
             << srv_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
        cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
        cout << "\tTotal data exchanged are " << total_data_size << " Bytes, " << total_data_size / 1024 << " KB, "
             << total_data_size / 1024 / 1024 << " MB " << endl << endl;
    }

    return 0;
}

int SSEBenchmark::benchmark_deletions()
{
    DianaDelClient diana_del_clnt;
    DianaDelServer diana_del_srv;
    unsigned char label[32], enc_id[80], enc_counter[64], F_k_w_ind[64], kw1[64];
    ConstrainedKey key;
    vector<ConstrainedKey *> range_keys;
    vector<string> plain_out, enc_counters;
    vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "2001";
    unordered_set<int> indices;

    //for every keywords, execute search
    cout << endl << endl << "Begin test deletions" << endl;
    for (double por:portion_to_del)
    {
        //set up the client and the server and load data
        diana_del_clnt.Setup();
        diana_del_srv.Setup();

        diana_del_clnt.load_data("dianadel_clnt_data");
        diana_del_srv.load_data("dianadel_srv_data");

        vector<string> &fnames = data_to_encrypt[keyword_to_delete];

        plain_out.clear();
        indices.clear();
        for(ConstrainedKey * ckey : range_keys)
            delete ckey;
        range_keys.clear();
        enc_counters.clear();

        plain_out.reserve(300000);
        indices.reserve(300000);
        range_keys.reserve(300000);
        enc_counters.reserve(300000);

        //generate delete ciphertexts
        this->randomly_select_deletions(indices, keyword_to_delete, por);
        for (auto &itr : indices)
        {
            diana_del_clnt.Delete(keyword_to_delete, fnames[itr], label, F_k_w_ind);
            diana_del_srv.Delete(label, F_k_w_ind);
        }

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        diana_del_clnt.trapdoor_for_diana_clnt_del(keyword_to_delete, &key, kw1);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = key.size() + 16; // kw1 is 16 Bytes


        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        diana_del_srv.SearchStage1(&key, kw1,enc_counters);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += enc_counters.size() * 32;

        //search stage 3: generat GGM trapdoor
        start = std::chrono::steady_clock::now();
        diana_del_clnt.trapdoor_for_diana_clnt(keyword_to_delete, enc_counters, range_keys, kw1);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        for(auto &it : range_keys)
        {
            total_data_size += it->size();
        }
        total_data_size += 16;

        //search stage 4: save re-encrypted cipehrtexts
        start = std::chrono::steady_clock::now();
        diana_del_srv.SearchStage2(range_keys, kw1, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch += elapsed.count();

        total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

        cout << "Searching for keyword: " << keyword_to_delete << endl;
        cout << "Deletion Portion: " << por << " and deleted entries is: " << int(por * fnames.size()) << endl;
        cout << "\tTotally find " << plain_out.size() << endl;
        cout << "\tTime cost of client is " << std::fixed << clnt_time_cost_in_srch << " us, average is "
             << clnt_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of server is " << fixed << srv_time_cost_in_srch << " us, average is "
             << srv_time_cost_in_srch / plain_out.size() << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << total_time_in_srch << " us" << endl;
        cout << "\tAverage time cost is " << fixed << total_time_in_srch / plain_out.size() << " us" << endl;
        cout << "\tTotal data exchanged are " << total_data_size << " bytes" << endl << endl;
    }


    return 0;
}

void SSEBenchmark::randomly_select_deletions(std::unordered_set<int> &indices, std::string &keyword, double por)
{
    vector<string> &t = this->data_to_encrypt[keyword];
    int total_number_filenames = t.size();
    int required_number = int(por * total_number_filenames);
    int cur_number = 0;
    int index = 0;

    if (required_number >= total_number_filenames)
    {
        required_number = total_number_filenames;
        for (int i = 0; i < total_number_filenames; i++)
            indices.emplace(i);
    }
    else
    {
        while (cur_number < required_number)
        {
            RAND_bytes((unsigned char *) &index, sizeof(int));
            index = index % total_number_filenames;
            if (index < 0)
                index = -index;
            if (indices.find(index) == indices.end())
            {
                indices.emplace(index);
                cur_number++;
            }
        }
    }
}
