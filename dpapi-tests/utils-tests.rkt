#lang racket/base

(require rackunit
         dpapi/private/utils)

;; =============================================================================
;; Padding Tests
;; =============================================================================

(test-case "pad empty bytes adds full block of padding"
  (define padded (pad-to-block-size #""))
  (check-equal? (bytes-length padded) 16)
  ;; All 16 bytes should be the padding value 16
  (for ([i (in-range 16)])
    (check-equal? (bytes-ref padded i) 16)))

(test-case "pad 1 byte"
  (define padded (pad-to-block-size #"\x41"))
  (check-equal? (bytes-length padded) 16)
  (check-equal? (bytes-ref padded 0) #x41)
  ;; 15 padding bytes, each with value 15
  (for ([i (in-range 1 16)])
    (check-equal? (bytes-ref padded i) 15)))

(test-case "pad 15 bytes"
  (define data (make-bytes 15 #xAA))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 16)
  ;; 1 padding byte with value 1
  (check-equal? (bytes-ref padded 15) 1))

(test-case "pad exactly 16 bytes adds full block of padding"
  (define data (make-bytes 16 #xBB))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 32)
  ;; Original data preserved
  (for ([i (in-range 16)])
    (check-equal? (bytes-ref padded i) #xBB))
  ;; 16 padding bytes, each with value 16
  (for ([i (in-range 16 32)])
    (check-equal? (bytes-ref padded i) 16)))

(test-case "pad 17 bytes"
  (define data (make-bytes 17 #xCC))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 32)
  ;; 15 padding bytes, each with value 15
  (for ([i (in-range 17 32)])
    (check-equal? (bytes-ref padded i) 15)))

(test-case "pad 31 bytes"
  (define data (make-bytes 31 #xDD))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 32)
  ;; 1 padding byte with value 1
  (check-equal? (bytes-ref padded 31) 1))

(test-case "pad 32 bytes adds full block"
  (define data (make-bytes 32 #xEE))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 48))

(test-case "pad 33 bytes"
  (define data (make-bytes 33 #xFF))
  (define padded (pad-to-block-size data))
  (check-equal? (bytes-length padded) 48))

;; =============================================================================
;; Unpadding Tests
;; =============================================================================

(test-case "unpad single block with full padding"
  (define padded (make-bytes 16 16))
  (define result (unpad-from-block-size padded))
  (check-equal? result #""))

(test-case "unpad single block with 1 byte padding"
  (define padded (bytes-append (make-bytes 15 #xAA) #"\x01"))
  (define result (unpad-from-block-size padded))
  (check-equal? (bytes-length result) 15)
  (for ([i (in-range 15)])
    (check-equal? (bytes-ref result i) #xAA)))

(test-case "unpad two blocks"
  (define padded (bytes-append (make-bytes 17 #x42) (make-bytes 15 15)))
  (define result (unpad-from-block-size padded))
  (check-equal? (bytes-length result) 17)
  (for ([i (in-range 17)])
    (check-equal? (bytes-ref result i) #x42)))

(test-case "unpad rejects non-block-aligned data"
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size (make-bytes 17 1)))))

(test-case "unpad rejects empty data"
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size #""))))

(test-case "unpad rejects zero padding value"
  (define bad (make-bytes 16 0))
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size bad))))

(test-case "unpad rejects padding value exceeding block size"
  (define bad (bytes-append (make-bytes 15 0) (bytes 17)))
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size bad))))

(test-case "unpad rejects inconsistent padding bytes"
  ;; Last byte says 3 bytes of padding, but not all 3 match
  (define bad (bytes-append (make-bytes 13 #xAA) #"\x01\x03\x03"))
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size bad))))

(test-case "unpad rejects partially inconsistent padding"
  ;; Last 4 bytes should all be 4, but one is wrong
  (define bad (bytes-append (make-bytes 12 #xBB) #"\x04\x04\x05\x04"))
  (check-exn exn:fail?
    (lambda () (unpad-from-block-size bad))))

;; =============================================================================
;; Round-Trip Tests
;; =============================================================================

(test-case "round-trip pad/unpad for various sizes"
  (for ([size (in-list '(0 1 2 15 16 17 31 32 33 100 255 256))])
    (define data (make-bytes size (modulo (+ size 1) 256)))
    (define result (unpad-from-block-size (pad-to-block-size data)))
    (check-equal? result data
                  (format "round-trip failed for size ~a" size))))

(test-case "round-trip preserves arbitrary byte content"
  (define data (apply bytes (for/list ([i (in-range 256)]) i)))
  (define result (unpad-from-block-size (pad-to-block-size data)))
  (check-equal? result data))

;; =============================================================================
;; Edge Cases and Properties
;; =============================================================================

(test-case "padded data length is always multiple of 16"
  (for ([size (in-range 0 100)])
    (define padded (pad-to-block-size (make-bytes size 0)))
    (check-equal? (modulo (bytes-length padded) 16) 0
                  (format "padded size not aligned for input size ~a" size))))

(test-case "padded data is always strictly larger than input"
  (for ([size (in-range 0 100)])
    (define padded (pad-to-block-size (make-bytes size 0)))
    (check-true (> (bytes-length padded) size)
                (format "padded data not larger for size ~a" size))))

(test-case "pad large data"
  (define data (make-bytes 10000 42))
  (define padded (pad-to-block-size data))
  ;; 10000 mod 16 = 0, so padding adds a full block
  (check-equal? (bytes-length padded) 10016)
  (define result (unpad-from-block-size padded))
  (check-equal? result data))
