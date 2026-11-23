package com.margelo.nitro.mobilecrypto

private const val COUNT_LIMIT_EXCLUSIVE = Int.MAX_VALUE + 1.0

internal fun Double.toCount(): Int {
  require(this >= 0 && this < COUNT_LIMIT_EXCLUSIVE) { "Expected a count from 0 to ${Int.MAX_VALUE}, got $this" }
  return toInt()
}
