#ifndef ENIGMA_UTIL_HPP
#define ENIGMA_UTIL_HPP

#if !defined(__cplusplus) || (__cplusplus < 201703L)
#error Minimum language standard requirement not met (C++17).
#endif

#include <numeric>

namespace util {

  // deduce_array_t ------------------------------------------------------------
  // Deduces a `std::array` type from the template parameter pack `Types`.
  //
  template<class ... Types>
  using deduce_array_t = std::array<
    std::common_type_t<Types...>, sizeof...(Types)>;

  // make_sorted_array ---------------------------------------------------------
  // Returns an array whose contents are those of the function parameter pack
  // `args` in default sorted order.
  //
  template<class ... Types>
  constexpr deduce_array_t<Types...>
  make_sorted_array(Types && ... args) {
    auto result = deduce_array_t<Types...>{std::forward<Types>(args)...};
    std::sort(result.begin(), result.end());
    return result;
  }

  // make_array_of -------------------------------------------------------------
  // Returns an array of `ValueT` elements. The array length is determined by
  // the number of elements in the function parameter pack `args`.
  //
  template<class ValueT, class ... Types>
  constexpr auto
  make_array_of(Types && ... args) -> std::array<ValueT, sizeof...(args)> {
    return {{static_cast<ValueT>(std::forward<Types>(args))...}};
  }

  // array_params --------------------------------------------------------------
  // Determines the template parameters of a standard library array type.
  // `T` shall be a `std::array` type.
  // `array_params<T>::type` shall be the type of the elements in `T`.
  // `array_params<T>::size` shall be the number of elements in `T`.
  //
  template<class T>
  class array_params {

    template<class>
    struct helper;

    template<class ValueT, std::size_t SizeV>
    struct helper<std::array<ValueT, SizeV>> {
      static constexpr std::size_t size = SizeV;
      using type = ValueT;
    };

    using helper_t = helper<std::decay_t<T>>;

  public:

    static constexpr std::size_t size = helper_t::size;
    using type = typename helper_t::type;
  };

  // array_value_t -------------------------------------------------------------
  // Determine the element type of a standard library array type.
  // `T` shall be a `std::array` type.
  //
  template<class T>
  using array_value_t = typename array_params<T>::type;

  // array_size_v --------------------------------------------------------------
  // Determine the number of elements in a standard library array type. 
  // `T` shall be a `std::array` type.
  //
  template<class T>
  inline constexpr std::size_t array_size_v = array_params<T>::size;

}

#endif // ENIGMA_UTIL_HPP