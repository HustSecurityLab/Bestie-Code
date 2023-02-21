#include <iostream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <string>
#include "trapdoor_permutation.h"
#include "sophos.h"
#include "fides.h"
#include "sse_benchmark.h"

using std::cout;
using std::endl;
using std::vector;
using std::string;

int test_fides_correctness()
{
    FidesClient fides_clnt;
    FidesServer fides_srv;
    char buf1[64];
    unsigned char label[32], cipher[80], st[256 + sizeof(size_t)], kw[32], IV[16];
    unsigned int counter;
    TdpPK pk;
    vector<string> cipher_out, plain_out;
    vector<string> labels, ciphers;

    fides_clnt.Setup();
    fides_srv.Setup();

    for (int i = 0; i < 200; i++)
    {
        sprintf(buf1, "000-%d", i);
        fides_clnt.update("abc", buf1, Fides_Add, label, IV, cipher);
        fides_srv.save(label, IV, cipher);
    }

    for (int i = 10; i < 20; i++)
    {
        sprintf(buf1, "000-%d", i);
        fides_clnt.update("abc", buf1, Fides_Del, label,IV, cipher);
        fides_srv.save(label, IV, cipher);
    }

    fides_clnt.search_stage1("abc", kw, st, counter);
    fides_clnt.get_pk(&pk);
    fides_srv.search(&pk, kw, st, counter, cipher_out);
    fides_clnt.search_stage2("abc", cipher_out, plain_out);
    fides_clnt.update_after_search("abc", plain_out, labels, ciphers);
    fides_srv.save(labels, ciphers);

    for (const auto &a:plain_out)
        cout << a << endl;

    fides_clnt.dump_data();
    fides_clnt.load_data();
    fides_srv.dump_data();
    fides_srv.load_data();

    cout << "----------------------------" << endl;

    FidesClient _fides_clnt;
    FidesServer _fides_srv;

    _fides_clnt.load_data();
    _fides_srv.load_data();
    cipher_out.clear();
    plain_out.clear();
    labels.clear();
    ciphers.clear();
    _fides_clnt.search_stage1("abc", kw, st, counter);
    _fides_clnt.get_pk(&pk);
    _fides_srv.search(&pk, kw, st, counter, cipher_out);
    _fides_clnt.search_stage2("abc", cipher_out, plain_out);

    _fides_clnt.update_after_search("abc", plain_out,labels,ciphers);

    for (const auto &a:plain_out)
        cout << a << endl;


    return 1;
}

int run_sse_benchmark(const string filename)
{
    SSEBenchmark bench;
    bench.Setup(filename);
    bench.benchmark_gen_add_cipher();
    bench.benchmark_gen_del_cipher();
    bench.benchmark_search();
    bench.benchmark_deletions();

    return 0;
}

int main()
{
    //test_fides_correctness();
    run_sse_benchmark("sse_data_lite");
    return 0;
}