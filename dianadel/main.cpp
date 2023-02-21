#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "constrained_prf.h"
#include "diana.h"
#include "dianadel.h"
#include "sse_benchmark.h"

extern "C"
{
#include <openssl/sha.h>
}

using namespace std;

int test_diana_del_correctness()
{
    DianaDelClient diana_del_clnt;
    DianaDelServer diana_del_srv;
    unsigned char label[32], enc_id[64], F_k_w_ind[32], enc_counter[16], enc_F_k_w_ind[32], IV[16];
    unsigned char kw1[64];
    char buf1[256];
    ConstrainedKey key;
    vector<string> enc_counters_to_del;
    vector<ConstrainedKey*> range_keys;
    vector<string> search_ret;

    diana_del_clnt.Setup();
    diana_del_srv.Setup();

    memset(enc_id, 0, 64);

    for(int i=0; i<4000; i++)
    {
        sprintf(buf1, "0001111-%d", i);
        diana_del_clnt.Add("abc", buf1, label, enc_id, F_k_w_ind, IV, enc_counter);
        diana_del_srv.Add(label, enc_id, F_k_w_ind, IV, enc_counter);
    }

    for(int i=1000; i<2000; i++)
    {
        sprintf(buf1, "0001111-%d", i);
        diana_del_clnt.Delete("abc", buf1, label, enc_F_k_w_ind);
        diana_del_srv.Delete(label, enc_F_k_w_ind);
    }

    diana_del_clnt.trapdoor_for_diana_clnt_del("abc", &key, kw1);

    diana_del_srv.SearchStage1(&key, kw1, enc_counters_to_del);
    diana_del_clnt.trapdoor_for_diana_clnt("abc", enc_counters_to_del, range_keys, kw1);
    diana_del_srv.SearchStage2(range_keys, kw1, search_ret);

    //for(auto _s:search_ret)
    //    cout << _s << endl;

    for(auto a:range_keys)
        delete a;

    cout << "---------------------" << endl;

    range_keys.clear();
    enc_counters_to_del.clear();
    search_ret.clear();

    diana_del_clnt.dump_data();
    diana_del_srv.dump_data();
    diana_del_clnt.load_data();
    diana_del_srv.load_data();

    diana_del_clnt.trapdoor_for_diana_clnt_del("abc", &key, kw1);
    diana_del_srv.SearchStage1(&key, kw1, enc_counters_to_del);
    diana_del_clnt.trapdoor_for_diana_clnt("abc", enc_counters_to_del, range_keys, kw1);
    diana_del_srv.SearchStage2(range_keys, kw1, search_ret);

    for(auto _s:search_ret)
        cout << _s << endl;

    cout << "size of results: " << search_ret.size() << endl;


    for(auto a:range_keys)
        delete a;

    return 1;
}

int run_sse_benchmark(const string &filename)
{
    SSEBenchmark bench;
    bench.Setup(filename);
    //bench.benchmark_gen_add_cipher();
    //bench.benchmark_gen_del_cipher();
    //bench.benchmark_search();
    bench.benchmark_deletions();

    return 0;
}

int main(int argc, char *argv[])
{
    //test_diana_del_correctness();
    run_sse_benchmark("sse_data_lite");
    return 0;
}
