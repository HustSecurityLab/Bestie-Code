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
#include "bestie.h"
extern "C"
{
#include "openssl/rand.h"
#include "openssl/sha.h"
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    char name[256], word[256];
    FILE *f_data = fopen(filename.c_str(), "r");
    BestieClient bestie_clnt;
    BestieServer bestie_srv;
    unsigned char label[32], D[36], C[80], IV[16];

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

    FILE *fp_clnt = fopen("mitra_star_clnt_data", "rb");
    FILE *fp_srv = fopen("mitra_star_srv_data", "rb");

    if (fp_clnt && fp_srv)
    {
        fclose(fp_clnt);
        fclose(fp_srv);
    }
    else
    {
        bestie_clnt.Setup();
        bestie_srv.Setup();
        for (const auto &a:data_to_encrypt)
        {
            for (const auto &f_name:a.second)
            {
                bestie_clnt.update(a.first, f_name, Bestie_Add, label, D, IV, C);
                bestie_srv.save(label, D, IV, C);
            }
        }
        bestie_clnt.dump_data("bestie_clnt_data");
        bestie_srv.dump_data("bestie_srv_data");
    }
    return 1;
}

int SSEBenchmark::benchmark_gen_add_cipher()
{
    BestieClient bestie_clnt;
    unsigned char label[32], D[36], C[80], IV[16];

    bestie_clnt.Setup();

    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            bestie_clnt.update(a.first, f_name, Bestie_Add, label, D, IV, C);
        }
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "encryption time cost: " << endl;
    cout << "\ttotally " << total_add_records << " records, total " << elapsed.count() << " us" << endl;
    cout << "\taverage time " << elapsed.count() / total_add_records << " us" << endl;
    cout << "length of a ciphertext is " << 32 + 32 + 16 + 64 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    BestieClient bestie_clnt;
    unsigned char label[32], D[32], C[68], IV[16];
    int _del_number = 0;

    bestie_clnt.Setup();

    bestie_clnt.load_data("bestie_clnt_data");

    auto start = std::chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            bestie_clnt.update(a.first, f_name, Bestie_Del, label, D, IV, C);
            _del_number++;

        }
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number << " us" << endl << endl;
    cout << "length of a deleting ciphertext is " << 32 + 32 + 16 + 64 << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    BestieClient bestie_clnt;
    BestieServer bestie_srv;
    vector<string> cipher_out, plain_out;
    unsigned char label[32], D[32], C[64], IV[16], K[32], loc_grp[32];
    unsigned int counter;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;

    bestie_clnt.load_data("bestie_clnt_data");
    bestie_srv.load_data("bestie_srv_data");

    for(auto &itr: this->data_to_encrypt)
    {
        cipher_out.clear();
        plain_out.clear();

        plain_out.reserve(300000);
        cipher_out.reserve(300000);

        bestie_clnt.Setup();
        bestie_srv.Setup();
        bestie_clnt.load_data("bestie_clnt_data");
        bestie_srv.load_data("bestie_srv_data");

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        bestie_clnt.trapdoor(itr.first, counter, K, loc_grp);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = sizeof(counter) + 32 + 32;

        //search stage 2:
        start = std::chrono::steady_clock::now();
        bestie_srv.search(counter, K, loc_grp, cipher_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * cipher_out[0].size();

        //search stage 3:
        start = std::chrono::steady_clock::now();
        bestie_clnt.decrypt(cipher_out, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        total_data_size += 64*cipher_out.size(); //returned file identifiers

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
    BestieClient bestie_clnt;
    BestieServer bestie_srv;
    vector<string> cipher_out, plain_out;
    unsigned char label[32], D[32], C[64], IV[16], K[32], loc_grp[32];
    unsigned int counter;
    vector<double> portion_to_del = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1};
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

        for(int i=0; i< 300000; i++)
        {
            SHA256((unsigned char*)&i, sizeof(int), label);
        }
        //set up the client and the server and load data
        cipher_out.clear();
        plain_out.clear();
        indices.clear();

        plain_out.reserve(300000);
        cipher_out.reserve(300000);
        indices.reserve(300000);

        bestie_clnt.Setup();
        bestie_srv.Setup();
        bestie_clnt.load_data("bestie_clnt_data");
        bestie_srv.load_data("bestie_srv_data");

        vector<string> &fnames = data_to_encrypt[keyword_to_delete];

        //generate delete ciphertexts
        this->randomly_select_deletions(indices, keyword_to_delete, por);
        for (auto &itr : indices)
        {
            bestie_clnt.update(keyword_to_delete, fnames[itr], Bestie_Del, label, D, IV, C);
            bestie_srv.save(label, D, IV, C);
        }

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        bestie_clnt.trapdoor(keyword_to_delete, counter, K, loc_grp);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = sizeof(counter) + 32 + 32;

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        bestie_srv.search(counter, K, loc_grp, cipher_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();
        total_data_size += cipher_out.size() * cipher_out[0].size();
        cout << " found " << cipher_out.size() << " ciphertexts" << endl;

        //search stage 3: decrypt ciphertexts
        start = std::chrono::steady_clock::now();
        bestie_clnt.decrypt(cipher_out, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        clnt_time_cost_in_srch += elapsed.count();
        total_data_size += 64*plain_out.size(); //returned file identifiers
        cout << plain_out[5] << endl;

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
        cout << "\tTotal data exchanged are " << total_data_size << " Bytes" << endl << endl;
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
