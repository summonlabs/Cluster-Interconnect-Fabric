// Cluster Interconnect Fabric (CIF) -- internal.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// Bounded multi-producer / single-consumer queue.
//
// Concurrency contract (this is the only lock the ingress path takes):
//   * The mutex protects the deque and the closed flag. It is a LEAF lock: no
//     other lock is ever acquired while it is held, and no user callback runs
//     under it.
//   * push() never blocks. Backpressure is reported to the caller, which is
//     what stops a slow reducer from deadlocking a producer.
//   * close() wakes every waiter so shutdown cannot hang.
#ifndef CIF_BOUNDED_QUEUE_HPP
#define CIF_BOUNDED_QUEUE_HPP

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <utility>

namespace cif {

template <typename T>
class BoundedQueue {
 public:
  explicit BoundedQueue(std::size_t capacity) : capacity_(capacity == 0 ? 1 : capacity) {}

  BoundedQueue(const BoundedQueue&) = delete;
  BoundedQueue& operator=(const BoundedQueue&) = delete;

  [[nodiscard]] bool push(T value) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (closed_ || queue_.size() >= capacity_) {
        return false;
      }
      queue_.push_back(std::move(value));
    }
    not_empty_.notify_one();
    return true;
  }

  /// Blocks until an item is available or the queue is closed. Returns false
  /// only when the queue is closed.
  [[nodiscard]] bool pop_wait(T& out) {
    std::unique_lock<std::mutex> lock(mutex_);
    not_empty_.wait(lock, [this] { return closed_ || !queue_.empty(); });
    if (queue_.empty()) {
      return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  /// Blocking wait with a deadline. Returns false on timeout (the queue stays
  /// open) or when the queue is empty and closed.
  template <typename Rep, typename Period>
  [[nodiscard]] bool pop_wait_for(T& out, const std::chrono::duration<Rep, Period>& deadline) {
    std::unique_lock<std::mutex> lock(mutex_);
    const bool signalled = not_empty_.wait_for(lock, deadline, [this] {
      return closed_ || !queue_.empty();
    });
    if (!signalled || queue_.empty()) {
      return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  [[nodiscard]] bool try_pop(T& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return false;
    }
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
  }

  /// Discards every pending item and reopens the queue. Only the owner of the
  /// queue may call this, and only when no producer is running.
  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.clear();
    closed_ = false;
  }

  void close() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      closed_ = true;
    }
    not_empty_.notify_all();
  }

  [[nodiscard]] bool closed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return closed_;
  }

  [[nodiscard]] std::size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

 private:
  mutable std::mutex mutex_;
  std::condition_variable not_empty_;
  std::deque<T> queue_;
  std::size_t capacity_;
  bool closed_ = false;
};

}  // namespace cif

#endif  // CIF_BOUNDED_QUEUE_HPP
