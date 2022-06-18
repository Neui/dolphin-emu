// Copyright 2008 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

// Most of the code in this file is from:
// GCNcrypt - GameCube AR Crypto Program
// Copyright (C) 2003-2004 Parasyte
// Renamed and modified to be on more modern standards

#include "Core/ARDecrypt.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "Common/BitUtils.h"
#include "Common/BitField.h"
#include "Common/CommonTypes.h"
#include "Common/MsgHandler.h"
#include "Common/StringUtil.h"
#include "Common/Swap.h"

namespace ActionReplay
{

namespace CRC
{
// It seems it isn't a real CRC implementation?

// AX.25 CRC16
constexpr std::array<u16, 0x10> crcax25{
    0x0000, 0x1081, 0x2102, 0x3183, 0x4204, 0x5285, 0x6306, 0x7387,
    0x8408, 0x9489, 0xA50A, 0xB58B, 0xC60C, 0xD68D, 0xE70E, 0xF78F,
};

// CRC-A
constexpr std::array<u16, 0x10> crca{
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
};

static u16 Generate(const u32* words, size_t size)
{
  u16 sum = 0;

  for (size_t w = 0; w < size; ++w)
  {
    for (int i = 0; i < 4; ++i)
    {
      u8 tmp = ((words[w] >> (i << 3)) ^ sum);
      sum = ((crcax25[(tmp >> 4) & 0x0F] ^ crca[tmp & 0x0F]) ^ (sum >> 8));
    }
  }

  return sum;
}
}  // namespace CRC


namespace DES
{
// Some names were taken from
// https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf

// Permuted choice 1
constexpr std::array<u8, 0x38> PC1{
    // First half for C_()
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    // Second half for D_()
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
};

// Permuted choice 2
constexpr std::array<u8, 0x30> PC2{
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
};

// Number of left shifts table, but previous shifts are added
constexpr std::array<u8, 0x10> rotations{
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

constexpr std::array<u32, 0x40> S0{
    0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400, 0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000, 0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000, 0x00010004, 0x00010400, 0x00000000, 0x01010004,
};
constexpr std::array<u32, 0x40> S1{
    0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000, 0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000, 0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020, 0x80000000, 0x80100020, 0x80108020, 0x00108000,
};
constexpr std::array<u32, 0x40> S2{
    0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000, 0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208, 0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000, 0x00020208, 0x00000008, 0x08020008, 0x00020200,
};
constexpr std::array<u32, 0x40> S3{
    0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081, 0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002000, 0x00802080,
};
constexpr std::array<u32, 0x40> S4{
    0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100, 0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000, 0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000, 0x00000000, 0x40080000, 0x02080100, 0x40000100,
};
constexpr std::array<u32, 0x40> S5{
    0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010, 0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000, 0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000, 0x20404000, 0x20000000, 0x00400010, 0x20004010,
};
constexpr std::array<u32, 0x40> S6{
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002, 0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802, 0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800, 0x04000002, 0x04000800, 0x00000800, 0x00200002,
};
constexpr std::array<u32, 0x40> S7{
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000, 0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000, 0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040, 0x00001040, 0x00040040, 0x10000000, 0x10041000,
};

using ProcessedKey = std::array<u32, 32>;

constexpr ProcessedKey ProcessKey(const std::array<u8, 8>& key)
{
  std::array<u8, 56> extracted{};
  ProcessedKey pkey{};

  // Extract using PC1
  for (size_t i = 0; i < extracted.size(); ++i)
  {
    const u8 bit = PC1[i] - 1;
    extracted[i] = Common::ExtractBit(key[bit >> 3], 7 - (bit & 7));
  }

  // Generate subkeys KS_n (key scheduler)
  for (int n = 0; n < 16; ++n)
  {
    std::array<u8, 56> subkey{};
    const u8 rotation = rotations[n];
    const auto half_subkey = subkey.size() / 2;

    // Roatate first half (C_n)
    for (size_t j = 0; j < half_subkey; ++j)
      subkey[j] = extracted[(j + rotation) % half_subkey];

    // Rotate second half (D_n)
    for (size_t j = 0; j < half_subkey; ++j)
      subkey[half_subkey + j] = extracted[half_subkey + ((j + rotation) % half_subkey)];

    // Combine C_n and D_n into KS_n using PC2 in some way...
    std::array<u8, 8> array2{};
    for (size_t j = 0; j < 8; ++j)
      array2[j] = 0;

    for (size_t j = 0; j < PC2.size(); ++j)
    {
      if (subkey[PC2[j] - 1] == 0)
      {
        continue;
      }

      const u8 tmp = ((j * 0x2AAB) >> 16) - (j >> 0x1F);
      const auto shift = j - (tmp * 6);
      array2[tmp] |= 1u << (7 - shift) >> 2;
    }

    pkey[n * 2] = (array2[0] << 24) | (array2[2] << 16) | (array2[4] << 8) | array2[6];
    pkey[n * 2 + 1] = (array2[1] << 24) | (array2[3] << 16) | (array2[5] << 8) | array2[7];
  }

  // Reverse first 32 bytes in 2-bytes chunks
  for (size_t i = 0, j = 32 - 2; i < 16; i += 2, j -= 2)
  {
    const auto prev = pkey[i];
    const auto prev2 = pkey[i + 1];
    pkey[i] = pkey[j];
    pkey[i + 1] = pkey[j + 1];
    pkey[j] = prev;
    pkey[j + 1] = prev2;
  }

  return pkey;
}

static void unscramble1(u32& a, u32& b)
{
  u32 tmp;

  b = Common::RotateLeft(b, 4);

  tmp = ((a ^ b) & 0xF0F0F0F0);
  a ^= tmp;
  b = Common::RotateRight((b ^ tmp), 20);

  tmp = ((a ^ b) & 0xFFFF0000);
  a ^= tmp;
  b = Common::RotateRight((b ^ tmp), 18);

  tmp = ((a ^ b) & 0x33333333);
  a ^= tmp;
  b = Common::RotateRight((b ^ tmp), 6);

  tmp = ((a ^ b) & 0x00FF00FF);
  a ^= tmp;
  b = Common::RotateLeft((b ^ tmp), 9);

  tmp = ((a ^ b) & 0xAAAAAAAA);
  a = Common::RotateLeft((a ^ tmp), 1);
  b ^= tmp;
}

static void unscramble2(u32& a, u32& b)
{
  u32 tmp;

  b = Common::RotateRight(b, 1);

  tmp = ((a ^ b) & 0xAAAAAAAA);
  b ^= tmp;
  a = Common::RotateRight((a ^ tmp), 9);

  tmp = ((a ^ b) & 0x00FF00FF);
  b ^= tmp;
  a = Common::RotateLeft((a ^ tmp), 6);

  tmp = ((a ^ b) & 0x33333333);
  b ^= tmp;
  a = Common::RotateLeft((a ^ tmp), 18);

  tmp = ((a ^ b) & 0xFFFF0000);
  b ^= tmp;
  a = Common::RotateLeft((a ^ tmp), 20);

  tmp = ((a ^ b) & 0xF0F0F0F0);
  b ^= tmp;
  a = Common::RotateRight((a ^ tmp), 4);
}

static void CryptBlock(const ProcessedKey pkey, u32 block[2])
{
  u32 a, b;
  u32 tmp, tmp2;
  int i = 0;

  a = Common::swap32(block[0]);
  b = Common::swap32(block[1]);
  unscramble1(a, b);

  while (i < 32)
  {
    tmp = Common::RotateRight(b, 4) ^ pkey[i++];
    tmp2 = (b ^ pkey[i++]);
    a ^= S6[tmp & 0x3F]
      ^ S4[(tmp >> 8) & 0x3F]
      ^ S2[(tmp >> 16) & 0x3F]
      ^ S0[(tmp >> 24) & 0x3F]
      ^ S7[tmp2 & 0x3F]
      ^ S5[(tmp2 >> 8) & 0x3F]
      ^ S3[(tmp2 >> 16) & 0x3F]
      ^ S1[(tmp2 >> 24) & 0x3F];

    tmp = Common::RotateRight(a, 4) ^ pkey[i++];
    tmp2 = a ^ pkey[i++];
    b ^= S6[tmp & 0x3F]
      ^ S4[(tmp >> 8) & 0x3F]
      ^ S2[(tmp >> 16) & 0x3F]
      ^ S0[(tmp >> 24) & 0x3F]
      ^ S7[tmp2 & 0x3F]
      ^ S5[(tmp2 >> 8) & 0x3F]
      ^ S3[(tmp2 >> 16) & 0x3F]
      ^ S1[(tmp2 >> 24) & 0x3F];
  }

  unscramble2(a, b);
  block[0] = Common::swap32(b);
  block[1] = Common::swap32(a);
}
}  // namespace DES


constexpr std::array<u8, 8> key{
    0x34, 0x1C, 0x84, 0x9E, 0xFD, 0xA4, 0xB6, 0x7B,
};

constexpr DES::ProcessedKey processedKey = DES::ProcessKey(key);

static u8 GenerateCodeChecksum(const u32* codes, size_t size)
{
  u16 sum = CRC::Generate(codes, size);
  return ((sum >> 12) ^ (sum >> 8) ^ (sum >> 4) ^ sum) & 0x0F;
}

union ARHeader {
  u64 raw;
  BitField<60, 4, u64> checksum;
  BitField<49, 11, u64> gameId;
  BitField<32, 17, u64> codeId;
  BitField<31, 1, u64> mastercode;
  BitField<30, 1, u64> unknown;
  BitField<28, 2, u64> region;
  BitField<0, 28, u64> leftover;
};

static bool DecryptCodes(u32* codes, size_t size)
{
  if ((size % 2) != 0)
    return false;

  if (!size)
    return false;

  u32* ptr = codes;
  const u32* const codes_end = codes + size;
  while (ptr < codes_end)
  {
    DES::CryptBlock(processedKey, ptr);
    ptr += 2;
  }

  ARHeader header = {(u64)codes[0] << 32 | codes[1]};

  // Grab gameid and region from the last decrypted code
  // TODO: Maybe check this against Dolphin's GameID? - "code is for wrong game" type msg
  // gameid = header.gameId;
  // region = header.region;

  codes[0] &= 0x0FFFFFFF;
  if (header.checksum != GenerateCodeChecksum(codes, size))
  {
    return false;
  }

  return true;

  // Unfinished (so says Parasyte :p )
}

// Alphanumeric filter for text<->bin conversion
constexpr std::string_view alphamap = "0123456789ABCDEFGHJKMNPQRTUVWXYZ";

static u8 CharToNum(const char chr)
{
  const auto ret = alphamap.find(chr);

  if (ret == alphamap.npos) {
    if (chr == 'I' || chr == 'L') {
      return 1;
    } else if (chr == 'O') {
      return 0;
    } else if (chr == 'S') {
      return 5;
    }
  }

  return ret;
}

static int AlphaToBin(std::vector<u32>& dst, const std::vector<std::string>& alpha)
{
  size_t line_number = 0; // 1-based
  u64 data;
  u8 parity;

  for (const auto& line : alpha)
  {
    line_number++;

    // Extract each 5 bits (ignore the very last bit)
    data = 0;
    for (int i = 0; i < 12; i++)
    {
      data |= (u64)CharToNum(line[i]) << (((12 - i) * 5) - 1);
    }
    data |= CharToNum(line[12]) >> 1;

    dst.emplace_back(data >> 32);
    dst.emplace_back(data & 0xFFFFFFFF);

    // Verify parity bit (very last bit)
    parity = 0;
    for (int i = 0; i < 64; i++)
    {
      parity ^= data >> i;
    }
    if ((parity & 1) != (CharToNum(line[12]) & 1))
    {
      return line_number;
    }
  }

  return 0;
}

void DecryptARCode(std::vector<std::string> vCodes, std::vector<AREntry>* ops)
{
  std::vector<u32> uCodes;
  uCodes.reserve(vCodes.size() * 2);

  for (std::string& s : vCodes)
  {
    Common::ToUpper(&s);
  }

  const u32 ret = AlphaToBin(uCodes, vCodes);
  if (ret)
  {
    // Return value is index + 1, 0 being the success flag value.
    PanicAlertFmtT(
        "Action Replay Code Decryption Error:\nParity Check Failed\n\nCulprit Code:\n{0}",
        vCodes[ret - 1]);
  }
  else if (!DecryptCodes(uCodes.data(), (u16)vCodes.size() * 2))
  {
    // Commented out since we just send the code anyways and hope for the best XD
    // PanicAlertFmt("Action Replay Code Decryption Error:\nCRC Check Failed\n\n"
    //               "First Code in Block (should be verification code):\n{}",
    //               vCodes[0]);

    for (size_t i = 0; i < uCodes.size(); i += 2)
    {
      ops->emplace_back(uCodes[i], uCodes[i + 1]);
      // PanicAlertFmt("Decrypted AR Code without verification code:\n{:08X} {:08X}", uCodes[i],
      //               uCodes[i + 1]);
    }
  }
  else
  {
    // Skip passing the verification code back
    for (size_t i = 2; i < uCodes.size(); i += 2)
    {
      ops->emplace_back(uCodes[i], uCodes[i + 1]);
      // PanicAlertFmt("Decrypted AR Code:\n{:08X} {:08X}", uCodes[i], uCodes[i+1]);
    }
  }
}

}  // namespace ActionReplay
