#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include "pun_prf.h"
#include "pun_encryption.h"
#include "constrained_prf.h"
#include "diana.h"
#include "januspp.h"
#include "sse_benchmark.h"

using std::cout;
using std::endl;
using std::string;
using std::vector;

int print_hex(unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("0x%02x ", data[i]);
    }
    printf("\n");

    return 0;
}

int test_januspp_correctness()
{
    unsigned char buf1[32], buf2[64], buf3[32], buf4[32], buf5[32], IV[16];
    char str_buf1[500];
    PunTag tag1;
    JanusPPClient januspp_clnt;
    JanusPPServer januspp_srv;
    ConstrainedKey trpd, trpd_del;
    vector<string> ret;

    januspp_clnt.Setup();
    januspp_srv.Setup();

    for (int i = 0; i < 100; i++)
    {
        cout << "add: " << i << endl;
        sprintf(str_buf1, "0020340-%d", i);
        januspp_clnt.Add("abc", buf1, string(str_buf1), IV, buf2, tag1);
        januspp_srv.SaveCipher(buf1, IV, buf2, tag1);
    }

    PuncturedKey *key_del = new PuncturedKey();

    for (int i = 10; i < 30; i++)
    {
        cout << "del: " << i << endl;
        sprintf(str_buf1, "0020340-%d", i);
        januspp_clnt.Delete("abc", buf1, string(str_buf1), key_del, tag1);
        januspp_srv.DeleteCipher(buf1, key_del, tag1);
        cout << i << endl;
    }

    for (int i = 34; i < 43; i++)
    {
        cout << "del: " << i << endl;
        sprintf(str_buf1, "0020340-%d", i);
        januspp_clnt.Delete("abc", buf1, string(str_buf1), key_del, tag1);
        januspp_srv.DeleteCipher(buf1, key_del, tag1);
        cout << i << endl;
    }

    delete key_del;

    januspp_clnt.dump_data();
    januspp_srv.dump_data();

    JanusPPClient _jc;
    JanusPPServer _js;

    _jc.Setup();
    _js.Setup();

    _jc.load_data();
    _js.load_data();


    _jc.trapdoor("abc", buf1, &trpd, buf2, &trpd_del, buf3);
    _js.Search(trpd, buf2, trpd_del, buf3, buf1, MAX_DELETESUPPORT, ret);

    cout << "searched: " << ret.size() << " --------------" << endl;

    for (auto a:ret)
        cout << a << endl;

    return 1;
}

int run_sse_benchmark(const string &filename)
{
    SSEBenchmark bench;
    bench.Setup(filename);
    bench.benchmark_gen_del_cipher();
    bench.benchmark_search();
    bench.benchmark_deletions();

    return 0;
}

int main(int argc, char *argv[])
{
    //test_januspp_correctness();
    run_sse_benchmark("sse_data_lite");
    return 0;
}
