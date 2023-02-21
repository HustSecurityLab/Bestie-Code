#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include "bestie.h"
#include "sse_benchmark.h"

using namespace std;

int test_bestie_correctness()
{
    unsigned char label[32], D[32], C[64], IV[16];
    unsigned char K[16], loc_grp[32];
    unsigned int counter;
    char buf1[512];
    vector<string> ret, search_ret;
    BestieClient bestie_clnt;
    BestieServer bestie_srv;

    bestie_clnt.Setup();
    bestie_srv.Setup();

    for (int i = 0; i < 4000; i++)
    {
        sprintf(buf1, "000033300-%d", i);
        bestie_clnt.update("abc", string(buf1), Bestie_Add, label, D, IV, C);
        bestie_srv.save(label, D, IV, C);
    }

    /* for (int i = 0; i < 300000; i++)
     {
         sprintf(buf1, "000033300-%d", i);
         bestie_clnt.update("abc", string(buf1), Bestie_Del, label, D, C);
         bestie_srv.save(label, D, C);
     }

     for (int i = 350000; i < 400000; i++)
     {
         sprintf(buf1, "000033300-%d", i);
         bestie_clnt.update("abc", string(buf1), Bestie_Del, label, D, C);
         bestie_srv.save(label, D, C);
     }*/

    bestie_clnt.dump_data();
    bestie_srv.dump_data();

    bestie_clnt.trapdoor("abc", counter, K, loc_grp);
    ret.reserve(400000);
    auto start = std::chrono::steady_clock::now();
    bestie_srv.search(counter, K, loc_grp, ret);
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "single time: " << elapsed.count() << endl;
    bestie_clnt.decrypt(ret, search_ret);

    for (auto &a: search_ret)
        cout << a << endl;

    bestie_clnt.Setup();
    bestie_clnt.load_data();
    bestie_srv.Setup();
    bestie_srv.load_data();

    search_ret.clear();
    ret.clear();

    bestie_clnt.trapdoor("abc", counter, K, loc_grp);
    bestie_srv.search(counter, K, loc_grp, ret);
    bestie_clnt.decrypt(ret, search_ret);

    cout << " --------------------------- searched " << search_ret.size() << " entries" << endl;
    for (auto &a: search_ret)
        cout << a << endl;

    return 1;
}

int test_bestie_parallel_correctness()
{
    unsigned char label[32], D[32], C[64], IV[16];
    unsigned char K[16], loc_grp[32];
    unsigned int counter;
    char buf1[512];
    vector<string> ret;
    vector<string> search_ret;
    BestieClient bestie_clnt;
    BestieServer bestie_srv;

    bestie_clnt.Setup();
    bestie_srv.Setup();

    for (int i = 0; i < 400; i++)
    {
        sprintf(buf1, "000033300-%d", i);
        bestie_clnt.update("abc", string(buf1), Bestie_Add, label, D, IV, C);
        bestie_srv.save(label, D, IV, C);
    }

    for (int i = 0; i < 300; i++)
    {
        sprintf(buf1, "000033300-%d", i);
        bestie_clnt.update("abc", string(buf1), Bestie_Del, label, D, IV, C);
        bestie_srv.save(label, D, IV, C);
    }

    for (int i = 0; i < 300; i++)
    {
        sprintf(buf1, "000033300-%d", i);
        bestie_clnt.update("abc", string(buf1), Bestie_Add, label, D, IV, C);
        bestie_srv.save(label, D, IV, C);
    }

    bestie_clnt.trapdoor("abc", counter, K, loc_grp);
    ret.reserve(400000);
    search_ret.reserve(400000);
    auto start = std::chrono::steady_clock::now();
    bestie_srv.search_in_parallel(counter, K, loc_grp, search_ret, 14);
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double, std::micro> elapsed = end - start;
    cout << "parallel time: " << elapsed.count() << endl;
    bestie_clnt.decrypt(search_ret, ret);

    cout << " --------------------------- searched " << search_ret.size() << " entries" << endl;
    for (auto &a: ret)
        cout << a << endl;

    return 1;
}

int run_sse_benchmark(const string filename)
{
    SSEBenchmark bench;
    bench.Setup(filename);
    //bench.benchmark_gen_add_cipher();
    //bench.benchmark_gen_del_cipher();
    //bench.benchmark_search();
    bench.benchmark_deletions();

    return 0;
}

int main()
{
    //run_sse_benchmark(0);

    //test_bestie_correctness();

    //run_sse_benchmark();

    run_sse_benchmark("sse_data_lite");

    return 0;
}