//
// Created by spiraldox on 9/2/19.
//

#ifndef DIANADEL_SSE_BENCHMARK_H
#define DIANADEL_SSE_BENCHMARK_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>

class SSEBenchmark
{
public:
    SSEBenchmark() = default;

    ~SSEBenchmark() = default;

    //read data and generate ciphertexts and local state
    int Setup(const std::string &filename);

    //time cost of generating add ciphertext
    int benchmark_gen_add_cipher();

    //time cost of generating delete ciphertext
    int benchmark_gen_del_cipher();

    //time cost of search with deletions
    int benchmark_deletions();

    //time cost of search without deletions
    int benchmark_search();

private:
    std::unordered_map<std::string, std::vector<std::string>> data_to_encrypt;
    void randomly_select_deletions(std::unordered_set<int> &indices, std::string &keyword, double por);
    int total_add_records = 0;
    int keyword_number = 0;

};

#endif //DIANADEL_SSE_BENCHMARK_H
