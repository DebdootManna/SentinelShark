#pragma once
#include <array>
#include <cstddef>
#include <cassert>
#include <stdexcept>

namespace SS {

/// Fixed-capacity ring buffer backed by std::array.
/// When full, push_back() overwrites the oldest element (no allocation, no blocking).
/// NOT thread-safe — must only be accessed from the GUI thread.
/// Access via operator[] is logical: index 0 = oldest element.
template<typename T, size_t N>
class RingBuffer {
    static_assert(N > 0, "RingBuffer capacity must be > 0");

public:
    RingBuffer() noexcept = default;

    /// Append item. If full, the oldest item is silently overwritten.
    void push_back(const T& item) noexcept {
        buf_[(head_ + size_) % N] = item;
        if (size_ < N) {
            ++size_;
        } else {
            head_ = (head_ + 1) % N; // advance head — oldest is gone
        }
    }

    void push_back(T&& item) noexcept {
        buf_[(head_ + size_) % N] = std::move(item);
        if (size_ < N) {
            ++size_;
        } else {
            head_ = (head_ + 1) % N;
        }
    }

    /// Logical index: 0 = oldest, size()-1 = newest.
    T& operator[](size_t logical_idx) noexcept {
        return buf_[(head_ + logical_idx) % N];
    }
    const T& operator[](size_t logical_idx) const noexcept {
        return buf_[(head_ + logical_idx) % N];
    }

    /// Newest element (last inserted).
    T& back() noexcept { return (*this)[size_ - 1]; }
    const T& back() const noexcept { return (*this)[size_ - 1]; }

    /// Oldest element.
    T& front() noexcept { return (*this)[0]; }
    const T& front() const noexcept { return (*this)[0]; }

    size_t size()     const noexcept { return size_; }
    bool   empty()    const noexcept { return size_ == 0; }
    bool   full()     const noexcept { return size_ == N; }
    static constexpr size_t capacity() noexcept { return N; }

    void clear() noexcept { head_ = 0; size_ = 0; }

private:
    std::array<T, N> buf_;
    size_t head_ = 0;   ///< Physical index of the oldest element
    size_t size_ = 0;   ///< Number of valid elements (0..N)
};

} // namespace SS
