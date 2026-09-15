#lang racket/base

;; Utility functions for DPAPI operations

(require "ffi.rkt"
         "errors.rkt")

(provide pad-to-block-size
         unpad-from-block-size
         zero-bytes!)

;; =============================================================================
;; PKCS#7 Padding for Block Cipher (16-byte blocks)
;; =============================================================================

(define (pad-to-block-size data)
  ;; Pad data to the next multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE (16 bytes)
  ;; using PKCS#7 padding
  (define len (bytes-length data))
  (define remainder (modulo len CRYPTPROTECTMEMORY_BLOCK_SIZE))
  (define padding-needed
    (if (zero? remainder)
        CRYPTPROTECTMEMORY_BLOCK_SIZE  ; Always add at least one block of padding
        (- CRYPTPROTECTMEMORY_BLOCK_SIZE remainder)))

  ;; Create padding bytes (each byte's value = padding length, per PKCS#7)
  (define padding (make-bytes padding-needed padding-needed))

  ;; Append padding to data
  (bytes-append data padding))

(define (unpad-from-block-size padded-data)
  ;; Remove PKCS#7 padding from padded data
  (define len (bytes-length padded-data))

  ;; Validate length is multiple of block size
  (unless (zero? (modulo len CRYPTPROTECTMEMORY_BLOCK_SIZE))
    (raise-dpapi-error 87 "unpad-from-block-size: data length not multiple of block size"))

  (when (zero? len)
    (raise-dpapi-error 87 "unpad-from-block-size: empty data"))

  ;; Read padding length from last byte
  (define padding-len (bytes-ref padded-data (- len 1)))

  ;; Validate padding length
  (when (or (zero? padding-len)
            (> padding-len CRYPTPROTECTMEMORY_BLOCK_SIZE))
    (raise-dpapi-error 13 "unpad-from-block-size: invalid padding length"))

  (when (> padding-len len)
    (raise-dpapi-error 13 "unpad-from-block-size: padding length exceeds data length"))

  ;; Validate all padding bytes have the same value
  (for ([i (in-range (- len padding-len) len)])
    (unless (= (bytes-ref padded-data i) padding-len)
      (raise-dpapi-error 13 "unpad-from-block-size: invalid padding bytes")))

  ;; Return data without padding
  (subbytes padded-data 0 (- len padding-len)))

(define (zero-bytes! bs)
  (for ([i (in-range (bytes-length bs))])
    (bytes-set! bs i 0)))
