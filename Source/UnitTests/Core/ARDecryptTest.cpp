// Copyright 2016 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <gtest/gtest.h>

#include <array>
#include <bitset>
#include <string>

#include "Core/ActionReplay.h"
#include "Core/ARDecrypt.h"

void CheckARCode(
    std::vector<std::string> code,
    std::vector<ActionReplay::AREntry> expected
    );

void CheckARCode(
    std::vector<std::string> code,
    std::vector<ActionReplay::AREntry> expected
    ) {
  std::vector<ActionReplay::AREntry> ops;
  DecryptARCode(code, &ops);
  ASSERT_EQ(ops, expected);
}

void WrongARCode(std::vector<std::string> code);

void WrongARCode(std::vector<std::string> code) {
  std::vector<ActionReplay::AREntry> ops;
  DecryptARCode(code, &ops);
  ASSERT_EQ(ops.size(), 0);
}

TEST(ARDecrypt, AvalancheDolphin)
{
  // See GTEP01.ini

  // Everything Unlocked
  CheckARCode({"ZFVYV6QHWDK53", "1Y7VQ40K0JAVX", "9HD2H7BEYK0JV"}, {
      ActionReplay::AREntry(0x0426ED18, 0x0004FFFF),
      ActionReplay::AREntry(0x0426ED1C, 0xFFFFFFFF)
      });

  // Infinite Lives
  CheckARCode({"KUNW0DJU5DXHD", "FYMVW1XMGQQ2R"}, {
      ActionReplay::AREntry(0x001A96C9, 0x00000003)
      });

  // Downhill Boost (Press X)
  CheckARCode({"V1KGNGP8D224P", "XCV70RNZ8ZPV6", "0T0FRWWBR8K2D"}, {
      ActionReplay::AREntry(0x3A235148, 0x00000400),
      ActionReplay::AREntry(0x04273248, 0x43D84BED)
      });

  // Time Trial: Found 5 Coin Pieces
  CheckARCode({"GZ5THADHNGPBM", "BAF8QT5K5N9WC"}, {
      ActionReplay::AREntry(0x022744D0, 0x00000005)
      });
}

TEST(ARDecrypt, WindWakerTCRF)
{
  // https://tcrf.net/index.php?title=The_Legend_of_Zelda:_The_Wind_Waker/Unused_Models&oldid=703517#Gryw00
  CheckARCode({"4RZ1G09A6XC9C", "2VWH64VC0EKF4"}, {
      ActionReplay::AREntry(0x04379518, 0x0090FF00)
      });

  CheckARCode({"8Z262CRF2TE20", "W7DGPFEP2E334"}, {
      ActionReplay::AREntry(0x04372838, 0x0090FF00)
      });

  CheckARCode({"Q4A5G16NAKMW6", "QDEF1V1TFUVF3"}, {
      ActionReplay::AREntry(0x04365CD8, 0x0090FF00)
      });

  // https://tcrf.net/index.php?title=The_Legend_of_Zelda:_The_Wind_Waker/Unused_Models&oldid=703517#Itnak
  CheckARCode({"7VTBNKXFF7W07", "5T12A4A528JM6"}, {
      ActionReplay::AREntry(0x0437A6D0, 0x018EFF00)
      });

  CheckARCode({"AHF4V3FM2JR95", "N3D5664B867M5"}, {
      ActionReplay::AREntry(0x043739F0, 0x018EFF00)
      });

  CheckARCode({"8VJQB3Y216XFY", "PRQ6FQY5XAT6R"}, {
      ActionReplay::AREntry(0x04366E90, 0x018EFF00)
      });

  // https://tcrf.net/index.php?title=The_Legend_of_Zelda:_The_Wind_Waker/Unused_Models&oldid=703517#Kt
  CheckARCode({"Y8JBQGU3F6P98", "3J0KTFK12NBFD"}, {
      ActionReplay::AREntry(0x04379EC0, 0x00B9FF00)
      });

  CheckARCode({"Q75X8886DE1H2", "RK2PY4UGUF0RE"}, {
      ActionReplay::AREntry(0x043731E0, 0x00B9FF00),
      });

  CheckARCode({"BR0ZC0ZEB8K1X", "VVDM8AD8P98GN"}, {
      ActionReplay::AREntry(0x04366680, 0x00B9FF00)
      });

  // https://tcrf.net/index.php?title=The_Legend_of_Zelda:_The_Wind_Waker/Unused_Models&oldid=703517#Syan
  CheckARCode({"AUPTEU14HVR2M", "1FWZFQFU0PWKN"}, {
      ActionReplay::AREntry(0x0437A6D0, 0x00B2FF00)
      });

  CheckARCode({"Y0Y1MMDUP8RQK", "YQ47W17ERFGPX"}, {
      ActionReplay::AREntry(0x043739F0, 0x00B2FF00)
      });

  CheckARCode({"D2X3DHE0ZYY58", "9PHPH9F1G6WCN"}, {
      ActionReplay::AREntry(0x04366E90, 0x00B2FF00)
      });

  // https://tcrf.net/index.php?title=The_Legend_of_Zelda:_The_Wind_Waker/Unused_Models&oldid=703517#Archive
  CheckARCode({"HV8R1RVZQEDGM", "Z3DE8GY8YAV71"}, {
      ActionReplay::AREntry(0x04379EC0, 0x01AEFF00)
      });

  CheckARCode({"EJ3NFTEEF1YVQ", "M0UNU1BXV9VYZ"}, {
      ActionReplay::AREntry(0x043731E0, 0x01AEFF00)
      });

  CheckARCode({"0ATFG5EU5R57G", "7RBCV4EZT2H0W"}, {
      ActionReplay::AREntry(0x04366680, 0x01AEFF00)
      });
}


TEST(ARDecrypt, WindWaker)
{
  // https://etherealgames.com/gcn/t/the-legend-of-zelda-the-wind-waker/action-replay-codes-us/

  // Press R to Jump
  CheckARCode({"7JDQV8NJBX9JT", "HA955EFJP9K3B", "E0WDR6Y36H61H"}, {
      ActionReplay::AREntry(0x0A3ED84A, 0x00000020),
      ActionReplay::AREntry(0x863E4410, 0x00000001)
      });

  // Press R to Mega Jump
  CheckARCode({"M0MVBZTBFC3RX", "HA955EFJP9K3B", "F424HF30Q00MN"}, {
      ActionReplay::AREntry(0x0A3ED84A, 0x00000020),
      ActionReplay::AREntry(0x863E4410, 0x00000003)
      });
}

TEST(ARDecrypt, Typos)
{
  WrongARCode({"7JDQV8NJBX9JT", "HA955EFJQ9K3B", "E0WDR6Y36H61H"});
}
