#pragma once
#include <atomic>
#include <array>
#include <cstddef>
#include <optional>

namespace SS {

/// Single-Producer Single-Consumer bounded lock-free queue.
/// try_push() returns false (packet dropped) when full — NEVER blocks.
/// try_pop()  returns false when empty.
/// The Capacity+1 trick avoids the ABA problem with head==tail disambiguation.
template<typename T, size_t Capacity>
class BoundedQueue {
    static_assert(Capacity > 0, "BoundedQueue capacity must be > 0");
    static constexpr size_t kSize = Capacity + 1; // one slot wasted to disambiguate full vs empty

public:
    BoundedQueue() noexcept
        : head_(0), tail_(0) {}

    /// Producer side: push item. Returns false and DROPS the item if queue is full.
    bool try_push(const T& item) noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t next = (head + 1) % kSize;
        if (next == tail_.load(std::memory_order_acquire))
            return false; // full — drop the packet
        buf_[head] = item;
        head_.store(next, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool try_push(T&& item) noexcept {
        const size_t head = head_.load(std::memory_order_relaxed);
        const size_t next = (head + 1) % kSize;
        if (next == tail_.load(std::memory_order_acquire))
            return false;
        buf_[head] = std::move(item);
        head_.store(next, std::memory_order_release);
        return true;
    }

    /// Consumer side: pop item into out. Returns false if empty.
    [[nodiscard]] bool try_pop(T& out) noexcept {
        const size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail == head_.load(std::memory_order_acquire))
            return false; // empty
        out = std::move(buf_[tail]);
        tail_.store((tail + 1) % kSize, std::memory_order_release);
        return true;
    }

    bool empty() const noexcept {
        return tail_.load(std::memory_order_acquire) ==
               head_.load(std::memory_order_acquire);
    }

    size_t approx_size() const noexcept {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t t = tail_.load(std::memory_order_relaxed);
        return (h >= t) ? (h - t) : (kSize - t + h);
    }

private:
    // Cache-line padding to prevent false sharing between producer and consumer
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    std::array<T, kSize> buf_;
};

} // namespace SS
