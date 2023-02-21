//
// Created by spiraldox on 8/30/19.
//

#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <chrono>
#include <set>
#include <random>
#include "sse_benchmark.h"
#include "januspp.h"
extern "C"
{
#include <openssl/rand.h>
}

using namespace std;

int SSEBenchmark::Setup(const std::string &filename)
{
    char name[256], word[256];
    FILE *f_data = fopen(filename.c_str(), "r");
    JanusPPClient januspp_clnt;
    JanusPPServer januspp_srv;
    unsigned char label[32], cipher[68], IV[16];
    PunTag tag;
    FILE *fp_clnt = fopen("januspp_clnt_data", "rb");
    FILE *fp_srv = fopen("januspp_srv_data", "rb");

    this->total_add_records = 0;
    this->data_to_encrypt.clear();

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
        cout << "skip encryption process" << endl;
    }
    else
    {
        januspp_clnt.Setup();
        januspp_srv.Setup();

        for(int i=0; i<1381588 - this->total_add_records; i++)
        {
            RAND_bytes(label, 32);
            RAND_bytes(IV, 16);
            RAND_bytes(cipher, 64);
            PunTag tag2(i);
            januspp_srv.SaveCipher(label, IV, cipher, tag2);
        }

        auto start = std::chrono::steady_clock::now();
        for (const auto &a:data_to_encrypt)
        {
            for (const auto &f_name:a.second)
            {
                januspp_clnt.Add(a.first, label, f_name, IV, cipher, tag);
                januspp_srv.SaveCipher(label, IV, cipher, tag);
            }
        }
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        cout << "encryption time cost: " << endl;
        cout << "\ttotal " << this->total_add_records << " records, total " << elapsed.count() << " us" << endl;
        cout << "\taverage time " << elapsed.count() / this->total_add_records << " us" << endl;
        cout << "length of a ciphertext is " << 16 + 64 + 32 + tag.size() << " bytes" << endl << endl;

        januspp_clnt.dump_data("januspp_clnt_data");
        januspp_srv.dump_data("januspp_srv_data");
    }
    return 1;
}

int SSEBenchmark::benchmark_gen_del_cipher()
{
    JanusPPClient januspp_clnt;
    unsigned char label[32], cipher[68], IV[16];
    PunTag tag;
    PuncturedKey psk;
    int _del_number = 0;

    januspp_clnt.Setup();
    januspp_clnt.load_data("januspp_clnt_data");

    auto start = chrono::steady_clock::now();
    for (const auto &a:data_to_encrypt)
    {
        for (const auto &f_name:a.second)
        {
            januspp_clnt.Delete(a.first, label, f_name, &psk, tag);

            _del_number++;
            if (_del_number == MAX_DELETESUPPORT)
                break;
        }
        if (_del_number == MAX_DELETESUPPORT)
            break;
    }
    auto end = chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;

    for (int i = 0; i < 2; i++)
    {
        _del_number = 0;
        januspp_clnt.Setup();
        januspp_clnt.load_data("januspp_clnt_data");
        start = chrono::steady_clock::now();
        for (const auto &a:data_to_encrypt)
        {
            for (const auto &f_name:a.second)
            {
                januspp_clnt.Delete(a.first, label, f_name, &psk, tag);

                _del_number++;
                if (_del_number == MAX_DELETESUPPORT)
                    break;
            }
            if (_del_number == MAX_DELETESUPPORT)
                break;
        }
        end = chrono::steady_clock::now();
        elapsed = elapsed + (end - start);
    }

    cout << "generating delete ciphertexts time cost: " << endl;
    cout << "\ttotal " << _del_number << ", time cost: " << elapsed.count() / 3 << " us" << endl;
    cout << "\taverage " << elapsed.count() / _del_number / 3 << " us" << endl << endl;
    cout << "length of a ciphertext is " << 32 + tag.size() + psk.size() << " bytes" << endl << endl;

    return 1;
}

int SSEBenchmark::benchmark_search()
{
    unsigned char label[32], ct[64], msk[32], kw1[32], kw1_del[32];
    ConstrainedKey trpd, trpd_del;
    PunTag tag;
    JanusPPServer januspp_srv;
    JanusPPClient januspp_clnt;
    vector<string> plain_out;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;

    //set up the client and the server and load data
    januspp_clnt.Setup();
    januspp_srv.Setup();

    januspp_clnt.load_data("januspp_clnt_data");
    januspp_srv.load_data("januspp_srv_data");

    //for every keywords, execute search
    for (auto &itr: this->data_to_encrypt)
    {
        plain_out.clear();

        plain_out.reserve(300000);

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        januspp_clnt.trapdoor(itr.first, msk, &trpd, kw1, &trpd_del, kw1_del);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = 32 * 3 + trpd.size() + trpd_del.size();

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        januspp_srv.Search(trpd, kw1, trpd_del, kw1_del, msk, MAX_DELETESUPPORT, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();

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
    unsigned char label[32], ct[64], msk[32], kw1[32], kw1_del[32];
    ConstrainedKey trpd, trpd_del;
    PunTag tag;
    PuncturedKey psk;
    JanusPPServer januspp_srv;
    JanusPPClient januspp_clnt;
    vector<string> plain_out;
    vector<int> number_to_del;
    double total_time_in_srch = 0;
    double clnt_time_cost_in_srch = 0;
    double srv_time_cost_in_srch = 0;
    unsigned int total_data_size = 0;
    string keyword_to_delete = "enterpris";
    unordered_set<int> indices;

    for (int i = 0; i <= 2000; i += 100)
    {
        number_to_del.push_back(i);
    }

    //for every keywords, execute search
    cout << endl << endl << "Begin test deletions" << endl;
    for (int num:number_to_del)
    {
        //set up the client and the server and load data
        januspp_clnt.Setup();
        januspp_srv.Setup();

        januspp_clnt.load_data("januspp_clnt_data");
        januspp_srv.load_data("januspp_srv_data");

        vector<string> &fnames = data_to_encrypt[keyword_to_delete];

        plain_out.clear();
        indices.clear();

        plain_out.reserve(300000);
        indices.reserve(300000);

        //generate delete ciphertexts
        this->randomly_select_deletions(indices, keyword_to_delete, num);
        for (auto &itr : indices)
        {
            januspp_clnt.Delete(keyword_to_delete, label, fnames[itr], &psk, tag);
            januspp_srv.DeleteCipher(label, &psk, tag);
        }

        //search stage 1: generate trapdoor
        auto start = std::chrono::steady_clock::now();
        januspp_clnt.trapdoor(keyword_to_delete, msk, &trpd, kw1, &trpd_del, kw1_del);
        auto end = std::chrono::steady_clock::now();
        std::chrono::duration<double, std::micro> elapsed = end - start;
        clnt_time_cost_in_srch = elapsed.count();
        total_data_size = 32 * 3 + trpd.size() + trpd_del.size();

        //search stage 2: find cipehrtexts
        start = std::chrono::steady_clock::now();
        januspp_srv.Search(trpd, kw1, trpd_del, kw1_del, msk, MAX_DELETESUPPORT, plain_out);
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        srv_time_cost_in_srch = elapsed.count();

        total_time_in_srch = clnt_time_cost_in_srch + srv_time_cost_in_srch;

        cout << "Searching for keyword: " << keyword_to_delete << endl;
        cout << "Deletion entries number: " << num << endl;
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

void SSEBenchmark::randomly_select_deletions(std::unordered_set<int> &indices, std::string &keyword, int num)
{
    vector<string> &t = this->data_to_encrypt[keyword];
    int total_number_filenames = t.size();
    int required_number = num;
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