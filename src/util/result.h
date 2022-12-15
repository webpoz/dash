// Copyright (c) 2018-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_RESULT_H
#define BITCOIN_UTIL_RESULT_H

#include <memory>

template<typename T>
struct Ok {
    static_assert(std::is_trivially_constructible<T>(), "T must be trivially constructable");
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
    static_assert(std::is_trivially_constructible<E>(), "E must be trivially constructable");
    E val_;
};

template<typename T, typename E>
class Result {
public:
    constexpr Result(Ok<T> val) : ok_(true), val_(val) {}
    constexpr Result(Err<E> err) : ok_(false), err_(err.val_) {}

    [[nodiscard]] constexpr bool is_ok() const { return ok_; }
    [[nodiscard]] constexpr bool is_err() const { return !ok_; }
    constexpr explicit operator bool() const {
        return is_ok();
    }
    [[nodiscard]] constexpr auto operator *() const -> T{
        return unwrap();
    }
    [[nodiscard]] constexpr auto unwrap() const -> T {
        assert(ok_);
        return val_.val_;
    }
    [[nodiscard]] constexpr auto unwrap_err() const -> E {
        assert(!ok_);
        return err_;
    }

private:
    bool ok_;
    Ok<T> val_;
    E err_;
};

#endif
