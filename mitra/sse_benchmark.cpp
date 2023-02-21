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
#include "mitra.h"
#include <unordered_set>
#include <iomanip>
extern "C"
{
#include <openssl/rand.h>
}

using namespace std;


int SSEBenchmark::Setup(const std::string &filename)
{
    char name[256], word[256];
    FILE *f_data = fopen(filename.c_str(), "r");

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

    unsigned char label[32], cipher[68];
    FILE *fp_clnt = fopen("mitra_clnt_data", "rb");
    FILE *fp_srv = fopen("mitra_srv_data", "rb");

    if (fp_clnt && fp_srv)
    {
        fclose(fp_clnt);
        fclose(fp_srv);
    }
    else
    {
        MitraClient mitra_clnt;
        MitraServer mitra_srv;

        mitra_clnt.Setup();
        mitra_srv.Setup();
        for (const auto &a:data_to_encrypt)
        {
            for (const auto &f_name:a.second)
            {
                mitra_clnt.update(a.first, f_name, Mitra_Add, label, cipher);
                mitra_srv.save(label, cipher);
            }
        }
        mitra_clnt.dump_data("mitra_clnt_data");
        mitra_srv.dump_data("mitra_srv_data");
    }
    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    MitraClient mitra_clnt;
    unsigned char label[32], cipher[66];
    int _add_number = 0;

    mitra_clnt.Setup();

    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            mitra_clnt.update(a.first, f_name, Mitra_Add, label, cipher);
            _add_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "encryption time cost: " << endl;
    cout << "\ttotally " << total_add_records << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / total_add_records << " us" << endl;
    cout << "length of a ciphertext is " << 32 + 66 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    MitraClient mitra_clnt;
    unsigned char label[32], cipher[66];
    int _del_number = 0;

    mitra_clnt.Setup();

    /*for (const auto &f_name:this->data_to_encrypt[this->keyword_to_del])
    {
        mitra_clnt.update(this->keyword_to_del, f_name, Mitra_Add, label, cipher);
    }*/


    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            mitra_clnt.update(a.first, f_name, Mitra_Del, label, cipher);
            _del_number++;
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number << " us" << endl << endl;
    cout << "length of a deleting ciphertext is " << 32 + 66 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    MitraClient mitra_clnt;
    MitraServer mitra_srv;
    vector<string> cipher_out, plain_out, tlist;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;

    //set up the client and the server and load data
    mitra_clnt.Setup();
    mitra_srv.Setup();

    mitra_clnt.load_data("mitra_clnt_data");
    mitra_srv.load_data("mitra_srv_data");

    //for every keywords, execute search
    for (auto &itr: this->data_to_encrypt)
    {
        cipher_out.clear();
        plain_out.clear();
        tlist.clear();

        cipher_out.reserve(300000);
        plain_out.reserve(300000);
        tlist.reserve(300000);

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        mitra_clnt.search_stage1(itr.first, tlist);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = tlist.size() * tlist[0].size();

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        mitra_srv.search(tlist, cipher_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * cipher_out[0].size();

        //search stage 3: decrypt ciphertexts
        start = std::chrono::steady_clock::now();
        mitra_clnt.search_stage2(itr.first, cipher_out, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        total_data_size += plain_out.size() * 64; //returned file identifiers

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
    MitraClient mitra_clnt;
    MitraServer mitra_srv;
    vector<string> cipher_out, plain_out, tlist;
    vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1};
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "2001";
    unsigned char label[32], cipher[66];
    unordered_set<int> indices;

    //for every keywords, execute search
    cout << endl << endl << "Begin test deletions" << endl;
    for (double por:portion_to_del)
    {
        //set up the client and the server and load data
        mitra_clnt.Setup();
        mitra_srv.Setup();

        mitra_clnt.load_data("mitra_clnt_data");
        mitra_srv.load_data("mitra_srv_data");

        vector<string> &fnames = data_to_encrypt[keyword_to_delete];

        cipher_out.clear();
        plain_out.clear();
        tlist.clear();
        indices.clear();

        cipher_out.reserve(300000);
        plain_out.reserve(300000);
        tlist.reserve(300000);
        indices.reserve(300000);

        //generate delete ciphertexts
        this->randomly_select_deletions(indices, keyword_to_delete, por);
        for (auto &itr : indices)
        {
            mitra_clnt.update(keyword_to_delete, fnames[itr], Mitra_Del, label, cipher);
            mitra_srv.save(label, cipher);
        }

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        mitra_clnt.search_stage1(keyword_to_delete, tlist);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = tlist.size() * tlist[0].size();

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        mitra_srv.search(tlist, cipher_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * cipher_out[0].size();

        //search stage 3: decrypt ciphertexts
        start = std::chrono::steady_clock::now();
        mitra_clnt.search_stage2(keyword_to_delete, cipher_out, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        total_data_size += plain_out.size() * 64; //returned file identifiers

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
        cout << "\tTotal data exchanged are " << total_data_size << " Bytes, " << total_data_size / 1024 << " KB, "
             << total_data_size / 1024 / 1024 << " MB " << endl << endl;
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

    if(required_number >= total_number_filenames)
    {
        required_number = total_number_filenames;
        for(int i=0; i<total_number_filenames; i++)
            indices.emplace(i);
    }
    else
    {
        while(cur_number < required_number)
        {
            RAND_bytes((unsigned char*)&index, sizeof(int));
            index = index % total_number_filenames;
            if (index < 0)
                index = -index;
            if (indices.find(index) == indices.end())
            {
                indices.emplace(index);
                cur_number ++;
            }
        }
    }
}

