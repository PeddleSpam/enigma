#ifndef ENIGMA_ENIGMA_HPP
#define ENIGMA_ENIGMA_HPP

#if !defined(__cplusplus) || (__cplusplus < 201703L)
#error Minimum language standard requirement not met (C++17).
#endif

#include <functional>
#include <cassert>
#include <bitset>

#include "util.hpp"

namespace enigma {

  using namespace util;

  // Rotor class ---------------------------------------------------------------
  // Represents a single rotor in an Enigma machine. A rotor implements a
  // cipher, where each code point (or character) is substituted for another.
  // This cipher may be offset by the rotation of the rotor. Notches may be
  // specified for any code point. If the rotor encounters any notches while
  // advancing it invokes the turnover callback (see `getTurnoverCallback` and
  // `setTurnoverCallback`). The turnover callback is programmable. It can be
  // used to link multiple rotors in an assembly such that each rotor advances
  // the one proceeding it.
  //
  // `IndexT` - The code point or "character" type. Must be an unsigned integer
  //            capable of representing the number of code points specified by
  //            `base`.
  // `base` - The number of code points on a rotor (e.g. 26 for the latin
  //          alphabet).
  //
  template<class IndexT, std::size_t base>
  class Rotor {
  public:

    static_assert(std::numeric_limits<IndexT>::max() >= base);
    static_assert(std::is_unsigned_v<IndexT>);
    static_assert(base > 0u);

    using Index = IndexT;
    using NotchArray = std::bitset<base>;
    using CipherArray = std::array<Index, base>;
    using TurnoverFunc = std::function<void(std::size_t)>;

    static constexpr std::size_t getBase() {
      return base;
    }

    Rotor() = delete;

    // Constructor --
    // `cipher` - An array of code points (`Index`) whose length is equal to
    //            `base`, or an object convertible to said type. The position
    //            and value of each element defines the mapping of code points
    //            from input to output (forward cipher).
    // `notches` - A bitset whose length is equal to `base`, or an object
    //             convertible to said type. Each bit indicates whether or not
    //             its corresponding code point has a notch.
    // `callback` - Optional callable of the form `void(std::size_t)`. Invoked
    //              by the `Rotor` object if one or more notches are
    //              encountered during advancement.
    //
    template<class CipherT, class NotchesT>
    Rotor(CipherT && cipher, NotchesT && notches,
          TurnoverFunc callback = ignoreTurnover):
        forward_cipher(std::forward<CipherT>(cipher)),
        notches(std::forward<NotchesT>(notches)),
        turnover_callback(std::move(callback)),
        position(0u) {

      for (auto i = 0u; i < cipher.size(); ++i) {
        reverse_cipher[cipher[i]] = i;
      }
    }

    [[nodiscard]] TurnoverFunc getTurnoverCallback() const {
      return turnover_callback;
    }

    void setTurnoverCallback(TurnoverFunc callback) {
      assert(callback);
      std::swap(callback, turnover_callback);
    }

    // advance --
    // Advance (rotate) the rotor by one step. Invoke the turnover callback if
    // a notch exists at the new position.
    //
    std::size_t advance() {
      assert(position < base);

      if (++position == base) {
        position = 0u;
      }

      if (notches[position]) {
        turnover_callback(1u);
      }

      return position;
    }

    // advance --
    // Advance (rotate) the rotor by `steps`. If any notches were encountered
    // invoke the turnover callback with the number of notches encountered.
    //
    std::size_t advance(std::size_t steps) {
      auto next = position + steps;
      auto knocks = (next / base) * notches.count();
      next = next % base;

      auto mask = ~NotchArray{};
      auto[lead, trail] = util::make_sorted_array(position, next);
      mask = (mask << (lead + (base - trail))) >> lead;
      mask = (next < position) ? ~mask : mask;
      knocks += (notches & mask).count();
      position = next;

      if (knocks > 0u) {
        turnover_callback(knocks);
      }

      assert(position < base);
      return position;
    }
    
    [[nodiscard]] Index doForwardCipher(Index val) const {
      assert(val < base);
      return forward_cipher[(position + val) % base];
    }

    [[nodiscard]] Index doReverseCipher(Index val) const {
      assert(val < base);
      return reverse_cipher[(position + val) % base];
    }

  private:

    static void ignoreTurnover(std::size_t) {}

    TurnoverFunc turnover_callback;
    CipherArray forward_cipher;
    CipherArray reverse_cipher;
    std::size_t position;
    NotchArray notches;
  };

  // Rotor class deduction guides ----------------------------------------------

  namespace {

    template<class T>
    class deduce_turnover_func {
      using rotor_t = Rotor<util::array_value_t<T>, util::array_size_v<T>>;
    public:
      using type = typename rotor_t::TurnoverFunc;
    };

    template<class T>
    using deduce_turnover_func_t = typename deduce_turnover_func<T>::type;

  }

  template<class T1, class T2>
  Rotor(T1 &&, T2 &&, deduce_turnover_func_t<T1> = {}) ->
    Rotor<util::array_value_t<T1>, util::array_size_v<T1>>;

  // Enigma Machine class ------------------------------------------------------
  // Contains a rotor assembly and a reflector. Rotors are connected such that
  // each advances the one following it. The reflector is used to reverse the
  // direction of encipherment. It takes the output of a forward pass through
  // the rotor assembly, and maps it to a new value ready for the reverse pass.
  //
  template<class IndexT, std::size_t base, std::size_t rotor_count>
  class EnigmaMachine {
  public:

    static_assert(std::numeric_limits<IndexT>::max() >= base);
    static_assert(std::is_unsigned_v<IndexT>);
    static_assert(base > 0u);

    using Index = IndexT;
    using RotorType = Rotor<Index, base>;
    using RotorArray = std::array<RotorType, rotor_count>;
    using ReflectorType = std::array<Index, base>;

    static constexpr std::size_t getBase() {
      return base;
    }

    static constexpr std::size_t getRotorCount() {
      return rotor_count;
    }

    EnigmaMachine() = delete;

    // Constructor --
    // `rotors` - A `std::array` of `Rotor` objects, or an object convertible
    //            to said type. Rotors are added to the assembly in the order
    //            they are received.
    // `reflector` - A `std::array` of code points (`Index`) whose length is
    //               equal to `base`, or an object convertible to said type.
    //
    template<class RotorsT, class ReflectorT>
    EnigmaMachine(RotorsT && rotors, ReflectorT && reflector):
        rotors(std::forward<RotorsT>(rotors)),
        reflector(std::forward<ReflectorT>(reflector)) {

      for (auto i = 0u; i < this->rotors.size() - 1; ++i) {
        auto & next_rotor = this->rotors[i + 1];
        auto callback = [&next_rotor](std::size_t knocks) {
          next_rotor.advance(knocks);
        };
        this->rotors[i].setTurnoverCallback(callback);
      }
    }

    void advance(std::size_t steps = 1u) {
      rotors[0].advance(steps);
    }

    // encode --
    // Encodes the input parameter `val` by passing it through the rotor
    // assembly twice. Once in the forward direction, and once in the reverse
    // direction, with the reflector being used to reverse direction between
    // passes.
    //
    [[nodiscard]] Index encode(Index val) const {

      // Encode forward through the rotor assembly.
      for (auto it = rotors.begin(); it != rotors.end(); ++it) {
        val = it->doForwardCipher(val);
      }

      // Reverse direction through the reflector.
      val = reflector[val];

      // Encode backwards through the rotor assembly.
      for (auto it = rotors.rbegin(); it != rotors.rend(); ++it) {
        val = it->doReverseCipher(val);
      }

      return val;
    }

    // encodeNext --
    // Single method to advance the rotor assembly and encode an input value.
    // To emulate the operations of a physical Enigma machine the rotor
    // assembly is advanced by one step before encoding the input.
    //
    Index encodeNext(Index val) {
      advance();
      return encode(val);
    }

  private:

    RotorArray rotors;
    ReflectorType reflector;
  };

  // Enigma Machine class deduction guides -------------------------------------

  namespace {

    template<class T>
    class deduce_rotor_params {

      template<class>
      struct helper;

      template<class IndexT, std::size_t BaseV>
      struct helper<Rotor<IndexT, BaseV>> {
        static constexpr std::size_t base = BaseV;
        using Index = IndexT;
      };

      using HelperT = helper<T>;

    public:
      static constexpr std::size_t base = HelperT::base;
      using Index = typename HelperT::Index;
    };

    template<class T>
    using deduce_rotor_index_t = typename deduce_rotor_params<T>::Index;

    template<class T>
    inline constexpr auto deduce_rotor_base_v = deduce_rotor_params<T>::base;

  }

  template<class T1, class T2>
  EnigmaMachine(T1 &&, T2 &&) ->
    EnigmaMachine<deduce_rotor_index_t<util::array_value_t<T1>>,
                  deduce_rotor_base_v<util::array_value_t<T1>>,
                  util::array_size_v<T1>>;

  // Generator class -----------------------------------------------------------
  // Adaptor for `EnigmaMachine` objects. Satisfies the interface requirements
  // of `UniformRandomBitGenerator`. Allows `EnigmaMachine` objects to be used
  // in standard library functions like `std::shuffle`.
  //
  template<class IndexT, std::size_t base, std::size_t rotor_count>
  class Generator {
  public:

    using MachineType = EnigmaMachine<IndexT, base, rotor_count>;
    using result_type = typename MachineType::Index;

    Generator() = delete;

    template<class MachineT>
    Generator(MachineT & machine, result_type seed):
        machine(machine), seq_val(seed) {}

    static constexpr result_type min() {
      return 0u;
    }

    static constexpr result_type max() {
      return base - 1u;
    }

    result_type operator()() {
      seq_val = machine.encodeNext(seq_val);
      return seq_val;
    }

  private:

    MachineType & machine;
    result_type seq_val;
  };

  // Generator class deduction guides ------------------------------------------

  template<class T> Generator(T &, typename T::Index) ->
    Generator<typename T::Index, T::getBase(), T::getRotorCount()>;

}

#endif // ENIGMA_ENIGMA_HPP