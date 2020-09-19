#if !defined(__cplusplus) || (__cplusplus < 201703L)
#error Minimum language standard requirement not met (C++17).
#endif

#include <algorithm>
#include <iostream>
#include <iterator>
#include <bitset>
#include <chrono>

#include "enigma.hpp"
#include "util.hpp"

// Rotor Wiring Tables ---------------------------------------------------------
// Numbers denote the letters of the latin alphabet (0 to 25). A letter at
// index `i` maps to (is substituted with) the value of `cipher[i]`.
// Source:
// https://en.wikipedia.org/wiki/Enigma_rotor_details#Rotor_wiring_tables

static auto const cipherI = util::make_array_of<std::uint8_t>(
  0x04, 0x0A, 0x0C, 0x05, 0x0B, 0x06, 0x03, 0x10, 0x15, 0x19, 0x0D, 0x13, 0x0E,
  0x16, 0x18, 0x07, 0x17, 0x14, 0x12, 0x0F, 0x00, 0x08, 0x01, 0x11, 0x02, 0x09
);

static auto const cipherII = util::make_array_of<std::uint8_t>(
  0x00, 0x09, 0x03, 0x0A, 0x12, 0x08, 0x11, 0x14, 0x17, 0x01, 0x0B, 0x07, 0x16,
  0x13, 0x0C, 0x02, 0x10, 0x06, 0x19, 0x0D, 0x0F, 0x18, 0x05, 0x15, 0x0E, 0x04
);

static auto const cipherIII = util::make_array_of<std::uint8_t>(
  0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x02, 0x0F, 0x11, 0x13, 0x17, 0x15, 0x19,
  0x0D, 0x18, 0x04, 0x08, 0x16, 0x06, 0x00, 0x0A, 0x0C, 0x14, 0x12, 0x10, 0x0E
);

static auto const reflectorB = util::make_array_of<std::uint8_t>(
  0x18, 0x11, 0x14, 0x07, 0x10, 0x12, 0x0B, 0x03, 0x0F, 0x17, 0x0D, 0x06, 0x0E,
  0x0A, 0x0C, 0x08, 0x04, 0x01, 0x05, 0x19, 0x02, 0x16, 0x15, 0x09, 0x00, 0x13
);

// Rotor Notch Tables ----------------------------------------------------------
// Bits indicate which code points on a rotor have notches. Declared in
// right-to-left order, such that far right bits correspond to the code point
// for the letter "A".
// Source:
// https://en.wikipedia.org/wiki/Enigma_rotor_details#Turnover_notch_positions

static auto const notchesI = std::bitset<cipherI.size()>{
  "00000000100000000000000000"
};

static auto const notchesII = std::bitset<cipherII.size()>{
  "00000000000000000000100000"
};

static auto const notchesIII = std::bitset<cipherIII.size()>{
  "00010000000000000000000000"
};

// -----------------------------------------------------------------------------

int main() {

  using namespace enigma;

  // Initialise the Enigma machine --

  auto machine = EnigmaMachine{
    std::array{
      Rotor{cipherIII, notchesIII},
      Rotor{cipherII, notchesII},
      Rotor{cipherI, notchesI}
    },
    reflectorB
  };

  using MachineType = decltype(machine);
  using SystemClock = std::chrono::system_clock;

  auto seed = SystemClock::now().time_since_epoch().count();
  machine.advance(seed);

  // Shuffle using PRNG adaptor for Enigma machine --

  using SeedLimits = std::numeric_limits<decltype(seed)>;
  seed /= (SeedLimits::max() / MachineType::getBase());

  auto items = std::array<int, 10u>{};
  std::iota(items.begin(), items.end(), 1);

  auto os_iter = std::ostream_iterator<int>(std::cout, ", ");
  std::copy(items.begin(), items.end(), os_iter);
  std::cout << "\n";

  std::shuffle(items.begin(), items.end(), Generator(machine, seed));
  std::copy(items.begin(), items.end(), os_iter);
  std::cout << "\n";

  return 0;
}
