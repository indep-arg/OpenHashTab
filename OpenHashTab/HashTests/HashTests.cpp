//    Copyright 2019-2025 namazso <admin@namazso.eu>
//    This file is part of OpenHashTab.
//
//    OpenHashTab is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    OpenHashTab is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with OpenHashTab.  If not, see <https://www.gnu.org/licenses/>.

// Regression tests for the hash algorithms.
//
// Every algorithm exposed by the UI is run over a fixed set of inputs, on every
// AlgorithmsDll flavor the current CPU can execute, as well as through the
// regular LegacyAlgorithms loader. All flavors must agree with each other, with
// a few well known test vectors and, unless generating, with a golden file.
//
// Usage:
//   HashTests --generate [out.txt]   write the golden file (stdout if omitted)
//   HashTests golden.txt             verify against the golden file

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <intrin.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <random>
#include <string>
#include <vector>

#include <Hasher.h>

extern "C" const HashAlgorithm* get_algorithms_begin_x86();
extern "C" const HashAlgorithm* get_algorithms_end_x86();
extern "C" const HashAlgorithm* get_algorithms_begin_SSE2();
extern "C" const HashAlgorithm* get_algorithms_end_SSE2();
extern "C" const HashAlgorithm* get_algorithms_begin_AVX2();
extern "C" const HashAlgorithm* get_algorithms_end_AVX2();
extern "C" const HashAlgorithm* get_algorithms_begin_AVX512();
extern "C" const HashAlgorithm* get_algorithms_end_AVX512();
extern "C" const HashAlgorithm* get_algorithms_begin_ARM64();
extern "C" const HashAlgorithm* get_algorithms_end_ARM64();

namespace {

template <uint64_t... Params>
constexpr uint64_t as_param[] = {Params...};

// Mirrors the table in LegacyHasher.cpp, which keeps its params private.
struct TestAlgorithm {
  const char* name;
  const char* alg_name;
  const uint64_t* params;
};

const TestAlgorithm k_test_algorithms[] = {
  {"CRC32", "CRC32", nullptr},
  {"CRC64", "CRC64", nullptr},
  {"XXH32", "XXH32", nullptr},
  {"XXH64", "XXH64", nullptr},
  {"XXH3-64", "XXH3-64", nullptr},
  {"XXH3-128", "XXH3-128", nullptr},
  {"MD4", "MD4", nullptr},
  {"MD5", "MD5", nullptr},
  {"RipeMD160", "RipeMD160", nullptr},
  {"SHA-1", "SHA-1", nullptr},
  {"SHA-224", "SHA-224", nullptr},
  {"SHA-256", "SHA-256", nullptr},
  {"SHA-384", "SHA-384", nullptr},
  {"SHA-512", "SHA-512", nullptr},
  {"Blake2sp", "BLAKE2sp", nullptr},
  {"SHA3-224", "Keccak", as_param<1152, 448, 224, 0x06>},
  {"SHA3-256", "Keccak", as_param<1088, 512, 256, 0x06>},
  {"SHA3-384", "Keccak", as_param<832, 768, 384, 0x06>},
  {"SHA3-512", "Keccak", as_param<576, 1024, 512, 0x06>},
  {"K12-264", "K12", as_param<264>},
  {"K12-256", "K12", as_param<256>},
  {"K12-512", "K12", as_param<512>},
  {"PH128-264", "PH128", as_param<8192, 264>},
  {"PH256-528", "PH256", as_param<8192, 528>},
  {"BLAKE3", "BLAKE3", as_param<256>},
  {"BLAKE3-512", "BLAKE3", as_param<512>},
  {"GOST 2012 (256)", "GOST 2012 (256)", nullptr},
  {"GOST 2012 (512)", "GOST 2012 (512)", nullptr},
  {"eD2k", "eD2k", nullptr},
  {"eD2k (Old)", "eD2k (Old)", nullptr},
  {"QuickXorHash", "QuickXorHash", nullptr},
};

static_assert(std::size(k_test_algorithms) == LegacyHashAlgorithm::k_count);

// Independently known digests, so that a broken golden file can't go unnoticed.
struct KnownVector {
  const char* name;
  const char* input;
  const char* hex;
};

const KnownVector k_known_vectors[] = {
  {"MD4", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
  {"MD5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
  {"SHA-1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
  {"SHA-256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
  {"SHA-512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
  {"SHA3-256", "empty", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
  {"BLAKE3", "empty", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"},
};

constexpr size_t k_ed2k_chunk = 9728000;

struct TestInput {
  std::string name;
  std::vector<uint8_t> data;
  bool chunked;
};

std::vector<uint8_t> make_random(size_t size) {
  std::mt19937_64 engine{0}; // NOLINT(cert-msc51-cpp)
  std::vector<uint8_t> v(size);
  for (size_t i = 0; i < size; i += 8) {
    auto r = engine();
    for (size_t j = 0; j < 8 && i + j < size; ++j, r >>= 8)
      v[i + j] = (uint8_t)r;
  }
  return v;
}

std::vector<TestInput> make_inputs() {
  std::vector<TestInput> inputs;
  inputs.push_back({"empty", {}, false});
  inputs.push_back({"abc", {'a', 'b', 'c'}, false});
  const auto mib = make_random(1 << 20);
  inputs.push_back({"1MiB", mib, false});
  inputs.push_back({"1MiB-chunked", mib, true});
  // Exactly one eD2k chunk is where eD2k and eD2k (Old) differ.
  inputs.push_back({"ed2k-exact", make_random(k_ed2k_chunk), false});
  inputs.push_back({"ed2k-span", make_random(2 * k_ed2k_chunk + 12345), true});
  return inputs;
}

std::string to_hex(const uint8_t* p, size_t n) {
  static constexpr char k_digits[] = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(k_digits[p[i] >> 4]);
    s.push_back(k_digits[p[i] & 0xF]);
  }
  return s;
}

void feed(HashBox& ctx, const TestInput& input) {
  const auto data = input.data.data();
  const auto size = input.data.size();
  if (!input.chunked) {
    ctx.Update(data, size);
    return;
  }
  // Irregular sizes around common block boundaries to exercise buffering.
  static constexpr size_t k_steps[] = {1, 7, 63, 64, 65, 127, 1000, 4095, 4096, 8193, 65537, 1 << 20};
  size_t off = 0;
  for (size_t i = 0; off < size; ++i) {
    const auto n = (std::min)(k_steps[i % std::size(k_steps)], size - off);
    ctx.Update(data + off, n);
    off += n;
  }
}

std::string run(HashBox ctx, const TestInput& input) {
  feed(ctx, input);
  uint8_t out[LegacyHashAlgorithm::k_max_size + 16]{};
  const auto size = ctx.GetOutputSize();
  if (size == 0 || size > LegacyHashAlgorithm::k_max_size)
    return "<bad output size>";
  ctx.Finish(out);
  return to_hex(out, size);
}

struct Flavor {
  const char* name;
  const HashAlgorithm* (*begin)();
  const HashAlgorithm* (*end)();
  bool supported;
};

#if defined(_M_X64)
bool cpu_has_avx2() {
  int r[4];
  __cpuidex(r, 0, 0);
  if (r[0] < 7)
    return false;
  __cpuidex(r, 1, 0);
  const auto osxsave_avx = (1 << 27) | (1 << 28);
  if ((r[2] & osxsave_avx) != osxsave_avx)
    return false;
  if ((_xgetbv(0) & 6) != 6)
    return false;
  __cpuidex(r, 7, 0);
  return (r[1] & (1 << 5)) != 0;
}

bool cpu_has_avx512() {
  if (!cpu_has_avx2())
    return false;
  int r[4];
  __cpuidex(r, 7, 0);
  const auto f_vl = (1u << 16) | (1u << 31);
  if (((uint32_t)r[1] & f_vl) != f_vl)
    return false;
  return (_xgetbv(0) & 0xE6) == 0xE6;
}
#endif

std::vector<Flavor> get_flavors() {
#if defined(_M_IX86)
  return {{"x86", &get_algorithms_begin_x86, &get_algorithms_end_x86, true}};
#elif defined(_M_X64)
  return {
    {"SSE2", &get_algorithms_begin_SSE2, &get_algorithms_end_SSE2, true},
    {"AVX2", &get_algorithms_begin_AVX2, &get_algorithms_end_AVX2, cpu_has_avx2()},
    {"AVX512", &get_algorithms_begin_AVX512, &get_algorithms_end_AVX512, cpu_has_avx512()},
  };
#elif defined(_M_ARM64)
  return {{"ARM64", &get_algorithms_begin_ARM64, &get_algorithms_end_ARM64, true}};
#else
#error "Unsupported architecture"
#endif
}

const HashAlgorithm* find(const Flavor& f, const char* alg_name) {
  for (auto it = f.begin(); it != f.end(); ++it)
    if (0 == strcmp(it->name, alg_name))
      return it;
  return nullptr;
}

using Key = std::pair<std::string, std::string>; // algorithm, input
using Results = std::map<Key, std::string>;

bool load_golden(const char* path, Results& golden) {
  FILE* f{};
  if (fopen_s(&f, path, "rb") || !f) {
    printf("ERROR: cannot open golden file %s\n", path);
    return false;
  }
  char line[1024];
  while (fgets(line, sizeof(line), f)) {
    std::string s = line;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
      s.pop_back();
    if (s.empty() || s[0] == '#')
      continue;
    const auto t1 = s.find('\t');
    const auto t2 = s.find('\t', t1 + 1);
    if (t1 == std::string::npos || t2 == std::string::npos)
      continue;
    golden[{s.substr(0, t1), s.substr(t1 + 1, t2 - t1 - 1)}] = s.substr(t2 + 1);
  }
  fclose(f);
  return !golden.empty();
}

} // namespace

int main(int argc, char** argv) {
  const bool generate = argc >= 2 && 0 == strcmp(argv[1], "--generate");
  const char* golden_path = generate ? nullptr : (argc >= 2 ? argv[1] : nullptr);
  const char* out_path = generate && argc >= 3 ? argv[2] : nullptr;

  if (!generate && !golden_path) {
    printf("usage: %s --generate [out.txt] | %s golden.txt\n", argv[0], argv[0]);
    return 2;
  }

  Results golden;
  if (golden_path && !load_golden(golden_path, golden))
    return 2;

  const auto inputs = make_inputs();
  const auto flavors = get_flavors();
  Results reference;
  int failures = 0;

  const auto check = [&](const char* source, const char* name, const TestInput& input, const std::string& hex) {
    const Key key{name, input.name};
    const auto ref = reference.find(key);
    if (ref == reference.end()) {
      reference[key] = hex;
    } else if (ref->second != hex) {
      printf("FAIL [%s] %s / %s: %s, other flavors gave %s\n", source, name, input.name.c_str(), hex.c_str(), ref->second.c_str());
      ++failures;
    }
  };

  for (const auto& f : flavors) {
    if (!f.supported) {
      printf("SKIP flavor %s (not supported by this CPU)\n", f.name);
      continue;
    }
    printf("Testing flavor %s\n", f.name);
    for (const auto& a : k_test_algorithms) {
      const auto alg = find(f, a.alg_name);
      if (!alg) {
        printf("FAIL [%s] algorithm %s not found\n", f.name, a.alg_name);
        ++failures;
        continue;
      }
      if (alg->ParamCheck(a.params) == 0) {
        printf("FAIL [%s] %s rejected its params\n", f.name, a.name);
        ++failures;
        continue;
      }
      for (const auto& input : inputs)
        check(f.name, a.name, input, run(alg->MakeContext(a.params), input));
    }
  }

  printf("Testing LegacyAlgorithms loader\n");
  for (const auto& la : LegacyHashAlgorithm::Algorithms())
    for (const auto& input : inputs)
      check("loader", la.GetName(), input, run(la.MakeContext(), input));

  for (const auto& kv : k_known_vectors) {
    const auto it = reference.find({kv.name, kv.input});
    if (it == reference.end() || it->second != kv.hex) {
      printf("FAIL known vector %s(%s): got %s, expected %s\n", kv.name, kv.input, it == reference.end() ? "<missing>" : it->second.c_str(), kv.hex);
      ++failures;
    }
  }

  if (generate) {
    FILE* out = stdout;
    if (out_path && (fopen_s(&out, out_path, "wb") || !out)) {
      printf("ERROR: cannot open %s for writing\n", out_path);
      return 2;
    }
    fprintf(out, "# OpenHashTab hash regression golden file. Format: algorithm<TAB>input<TAB>hex\n");
    for (const auto& a : k_test_algorithms)
      for (const auto& input : inputs)
        fprintf(out, "%s\t%s\t%s\n", a.name, input.name.c_str(), reference[{a.name, input.name}].c_str());
    if (out != stdout)
      fclose(out);
  } else {
    for (const auto& [key, hex] : reference) {
      const auto it = golden.find(key);
      if (it == golden.end()) {
        printf("FAIL %s / %s: missing from golden file\n", key.first.c_str(), key.second.c_str());
        ++failures;
      } else if (it->second != hex) {
        printf("FAIL %s / %s: got %s, golden %s\n", key.first.c_str(), key.second.c_str(), hex.c_str(), it->second.c_str());
        ++failures;
      }
    }
  }

  printf("%s: %d failure(s), %zu results checked\n", failures ? "FAILED" : "PASSED", failures, reference.size());
  return failures ? 1 : 0;
}
