// psl_parity_test.cpp — assert the C++ public-suffix matcher (public_suffix.cpp)
// resolves suffix/domain identically to tldextract (include_psl_private_domains
// = False) over a curated + random host sample. Fixtures generated from the SAME
// bundled snapshot the codegen reads (scripts/gen_psl_data.py). Issue #13.
//
// Standalone ctest executable: returns 0 on PASS, 1 on FAIL.

#include <cstdio>
#include <string>
#include <string_view>

#include "public_suffix.h"

using dexkit::ext::PublicSuffixExtract;

namespace {
struct Case {
    const char* host;
    const char* suffix;
    const char* domain;
};

// GENERATED (scripts snippet in the commit) — host -> (tldextract suffix, domain).
constexpr Case kCases[] = {
    {"example.com", "com", "example"},
    {"a.co.uk", "co.uk", "a"},
    {"forums.news.cnn.com", "com", "cnn"},
    {"foo.blogspot.com", "com", "blogspot"},
    {"os.name", "name", "os"},
    {"com.google.util", "", "util"},
    {"www.ck", "ck", "www"},
    {"foo.ck", "foo.ck", ""},
    {"x.foo.ck", "foo.ck", "x"},
    {"city.kobe.jp", "kobe.jp", "city"},
    {"a.city.kobe.jp", "kobe.jp", "city"},
    {"b.kobe.jp", "b.kobe.jp", ""},
    {"foo.xn--p1ai", "xn--p1ai", "foo"},
    {"a.b.xn--p1ai", "xn--p1ai", "b"},
    {"sub.github.io", "io", "github"},
    {"github.io", "io", "github"},
    {"test.onion", "onion", "test"},
    {"x.y.pvt.k12.ma.us", "pvt.k12.ma.us", "y"},
    {"localhost", "", "localhost"},
    {"single", "", "single"},
    {"a.bd", "a.bd", ""},
    {"x.a.bd", "a.bd", "x"},
    {"foo.nom.br", "foo.nom.br", ""},
    {"x.foo.nom.br", "foo.nom.br", "x"},
    {"evil.tk", "tk", "evil"},
    {"a.b.c.d.example.com", "com", "example"},
    {"trailing.com.", "com", "trailing"},
    {"aeroport.ci", "ci", "aeroport"},
    {"host80.sardinia.it", "sardinia.it", "host80"},
    {"host7.org.ba", "org.ba", "host7"},
    {"host87.trapani.it", "trapani.it", "host87"},
    {"host3.kouzushima.tokyo.jp", "kouzushima.tokyo.jp", "host3"},
    {"host82.play", "play", "host82"},
    {"host26.pwc", "pwc", "host26"},
    {"host26.uryu.hokkaido.jp", "uryu.hokkaido.jp", "host26"},
    {"host14.edu.hn", "edu.hn", "host14"},
    {"host37.yoshinogari.saga.jp", "yoshinogari.saga.jp", "host37"},
    {"host26.kainan.wakayama.jp", "kainan.wakayama.jp", "host26"},
    {"host58.lecco.it", "lecco.it", "host58"},
    {"host96.shimabara.nagasaki.jp", "shimabara.nagasaki.jp", "host96"},
    {"host73.kofu.yamanashi.jp", "kofu.yamanashi.jp", "host73"},
    {"host41.inuyama.aichi.jp", "inuyama.aichi.jp", "host41"},
    {"host2.lib.or.us", "lib.or.us", "host2"},
    {"host79.togakushi.nagano.jp", "togakushi.nagano.jp", "host79"},
    {"host43.fujieda.shizuoka.jp", "fujieda.shizuoka.jp", "host43"},
    {"host56.wsse.gov.pl", "wsse.gov.pl", "host56"},
    {"host74.sor-fron.no", "sor-fron.no", "host74"},
    {"host30.kota.aichi.jp", "kota.aichi.jp", "host30"},
    {"host71.co.bz", "co.bz", "host71"},
    {"host6.mil.az", "mil.az", "host6"},
    {"host72.shimamoto.osaka.jp", "shimamoto.osaka.jp", "host72"},
    {"host93.london", "london", "host93"},
    {"host83.biz", "biz", "host83"},
    {"host40.nom.ro", "nom.ro", "host40"},
    {"host28.tokushima.jp", "tokushima.jp", "host28"},
    {"host79.support", "support", "host79"},
    {"host24.kayabe.hokkaido.jp", "kayabe.hokkaido.jp", "host24"},
    {"host68.lv", "lv", "host68"},
    {"host68.luxe", "luxe", "host68"},
    {"host68.valle.no", "valle.no", "host68"},
    {"host24.ishikari.hokkaido.jp", "ishikari.hokkaido.jp", "host24"},
    {"host85.store.nf", "store.nf", "host85"},
    {"host7.ai.vn", "ai.vn", "host7"},
    {"host96.kinokawa.wakayama.jp", "kinokawa.wakayama.jp", "host96"},
    {"host64.reit", "reit", "host64"},
    {"host91.com.bn", "com.bn", "host91"},
    {"host95.nagatoro.saitama.jp", "nagatoro.saitama.jp", "host95"},
    {"host75.gr", "gr", "host75"},
    {"host59.edu.pl", "edu.pl", "host59"},
    {"host4.its.me", "its.me", "host4"},
    {"host67.taketa.oita.jp", "taketa.oita.jp", "host67"},
    {"host63.theater", "theater", "host63"},
    {"host70.royrvik.no", "royrvik.no", "host70"},
    {"host97.mv", "mv", "host97"},
    {"host84.romsa.no", "romsa.no", "host84"},
    {"host94.hayashima.okayama.jp", "hayashima.okayama.jp", "host94"},
    {"host46.freight.aero", "freight.aero", "host46"},
    {"host95.org.sz", "org.sz", "host95"},
    {"host72.biz.pl", "biz.pl", "host72"},
    {"host73.shinjo.okayama.jp", "shinjo.okayama.jp", "host73"},
    {"host83.omega", "omega", "host83"},
    {"host33.sasebo.nagasaki.jp", "sasebo.nagasaki.jp", "host33"},
    {"host34.praxi", "praxi", "host34"},
    {"host9.yokoze.saitama.jp", "yokoze.saitama.jp", "host9"},
    {"host91.association.aero", "association.aero", "host91"},
    {"host17.boleslawiec.pl", "boleslawiec.pl", "host17"},
    {"host8.malvik.no", "malvik.no", "host8"},
    {"host22.social", "social", "host22"},
};

int fails = 0;
void check(const Case& c) {
    auto r = PublicSuffixExtract(c.host);
    if (r.suffix != c.suffix || r.domain != c.domain) {
        std::printf("FAIL %-32s got suffix=%-16s domain=%-14s want suffix=%-16s domain=%s\n",
                    c.host, r.suffix.c_str(), r.domain.c_str(), c.suffix, c.domain);
        ++fails;
    }
    // HasRegisteredDomain consistency: true iff both non-empty.
    bool want_reg = c.suffix[0] != '\0' && c.domain[0] != '\0';
    if (r.HasRegisteredDomain() != want_reg) {
        std::printf("FAIL %-32s HasRegisteredDomain=%d want=%d\n", c.host,
                    r.HasRegisteredDomain(), want_reg);
        ++fails;
    }
}
}  // namespace

int main() {
    for (const auto& c : kCases) check(c);
    int n = static_cast<int>(sizeof(kCases) / sizeof(kCases[0]));
    if (fails) {
        std::printf("psl_parity_test: %d/%d FAILED\n", fails, n);
        return 1;
    }
    std::printf("psl_parity_test: %d/%d checks passed\n", n, n);
    return 0;
}
