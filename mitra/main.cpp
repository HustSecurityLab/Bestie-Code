#include <iostream>
#include <iostream>
#include <vector>
#include <string>
#include "mitra.h"
#include "sse_benchmark.h"

using namespace std;

int test_mitra_correctness()
{
    unsigned char label[32], cipher[66];
    char buf1[512];
    vector<string> tlist, ret, Fw;

    MitraClient mitra_clnt;
    MitraServer mitra_srv;

    mitra_clnt.Setup();
    mitra_srv.Setup();

    tlist.reserve(300000);
    ret.reserve(300000);
    Fw.reserve(300000);

    for (int i = 0; i < 100000; i++)
    {
        sprintf(buf1, "0001--%d", i);

        mitra_clnt.update("abc", buf1, Mitra_Add, label, cipher);
        mitra_srv.save(label, cipher);
    }

    for (int i = 8000; i < 100000; i++)
    {
        sprintf(buf1, "0001--%d", i);

        mitra_clnt.update("abc", buf1, Mitra_Del, label, cipher);
        mitra_srv.save(label, cipher);
    }

    mitra_clnt.search_stage1("abc", tlist);
    mitra_srv.search(tlist, Fw);
    mitra_clnt.search_stage2("abc", Fw, ret);

    for (const auto &a:ret)
        cout << a << endl;

    cout << "---------------------------------" << endl;
    cout << "result size: " << ret.size() << endl;

    Fw.clear();
    ret.clear();
    tlist.clear();

    mitra_clnt.dump_data();
    mitra_clnt.Setup();
    mitra_clnt.load_data();
    mitra_srv.dump_data();
    mitra_srv.Setup();
    mitra_srv.load_data();

    mitra_clnt.search_stage1("abc", tlist);
    mitra_srv.search(tlist, Fw);
    mitra_clnt.search_stage2("abc", Fw, ret);

    for (const auto &a:ret)
        cout << a << endl;

    cout << "---------------------------------" << endl;
    cout << "result size: " << ret.size() << endl;

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
    run_sse_benchmark("sse_data_lite");
    return 0;
}