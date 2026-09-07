#pragma once
#include <mutex>
#include <array>
#include <cstddef>
#include <utility>

namespace SS {

/// Thread-safe bounded queue strictly protected by std::mutex.
/// try_push() drops the packet and returns false when full (drop-tail, never blocks).
/// try_pop() returns false when empty.
/// clear() empties the queue under lock.
/// mutex() exposes the underlying std::mutex for explicit lock_guard scoping.
template<typename T, size_t Capacity>
class BoundedQueue {
    static_assert(Capacity > 0, "BoundedQueue capacity must be > 0");
    static constexpr size_t kSize = Capacity + 1; // disambiguate full vs empty

public:
    BoundedQueue() noexcept
        : head_(0), tail_(0) {}

    /// Producer side: push item. Returns false and DROPS the item if queue is full.
    bool try_push(const T& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t next = (head_ + 1) % kSize;
        if (next == tail_)
            return false; // full — drop the packet
        buf_[head_] = item;
        head_ = next;
        return true;
    }

    [[nodiscard]] bool try_push(T&& item) {
        std::lock_guard<std::mutex> lock(mutex_);
        const size_t next = (head_ + 1) % kSize;
        if (next == tail_)
            return false;
        buf_[head_] = std::move(item);
        head_ = next;
        return true;
    }

    /// Consumer side: pop item into out under lock. Returns false if empty.
    [[nodiscard]] bool try_pop(T& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        return try_pop_internal(out);
    }

    /// Pop without internal lock — caller MUST hold mutex().
    [[nodiscard]] bool try_pop_unlocked(T& out) noexcept {
        return try_pop_internal(out);
    }

    /// Empty the queue under lock.
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        clear_unlocked();
    }

    /// Empty the queue without internal lock — caller MUST hold mutex().
    void clear_unlocked() noexcept {
        head_ = 0;
        tail_ = 0;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tail_ == head_;
    }

    size_t approx_size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return (head_ >= tail_) ? (head_ - tail_) : (kSize - tail_ + head_);
    }

    /// Expose mutex for external synchronization (e.g., in Stop or Clear routines).
    std::mutex& mutex() noexcept {
        return mutex_;
    }

private:
    bool try_pop_internal(T& out) noexcept {
        if (tail_ == head_)
            return false; // empty
        out = std::move(buf_[tail_]);
        tail_ = (tail_ + 1) % kSize;
        return true;
    }

    mutable std::mutex mutex_;
    size_t head_{0};
    size_t tail_{0};
    std::array<T, kSize> buf_;
};

} // namespace SS
