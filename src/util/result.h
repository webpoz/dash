// Copyright (c) 2018-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_RESULT_H
#define BITCOIN_UTIL_RESULT_H

#include <cassert>
#include <utility> // for std::move()
#include <variant>

template<typename T>
struct Ok {
    constexpr explicit Ok(T val) : val_(std::move(val)) {}
    T val_;
};

// Specialization of the Ok struct for void type
template<>
struct Ok<void> {
    constexpr Ok() = default;
};

template<typename E>
struct Err {
    constexpr explicit Err(E val) : val_(std::move(val)) {}
    E val_;
};

template<typename T, typename E>
class Result {
public:
    constexpr Result(Ok<T> val) : val_(std::variant<Ok<T>, E>(val)) {}
    constexpr Result(Err<E> err) : val_(std::variant<Ok<T>, E>(err.val_)) {}

    [[nodiscard]] constexpr bool is_ok() const { return std::holds_alternative<Ok<T>>(val_); }
    [[nodiscard]] constexpr bool is_err() const { return !is_ok(); }
    constexpr explicit operator bool() const {
        return is_ok();
    }
    [[nodiscard]] constexpr auto operator *() const -> T{
        return unwrap();
    }
    [[nodiscard]] constexpr auto unwrap() const -> T {
        assert(is_ok());
        return std::get<T>(val_).val_;
    }
    [[nodiscard]] constexpr auto unwrap_err() const -> E {
        assert(is_err());
        return std::get<E>(val_);
    }

private:
    std::variant<Ok<T>, E> val_;
};

#endif
