#lang racket/base

(require rackunit
         dpapi/private/memory-protect
         dpapi/main)

;; =============================================================================
;; Memory Protection Tests (require Windows)
;; =============================================================================

(when (dpapi-available?)

  ;; ---------------------------------------------------------------------------
  ;; Basic Round-Trip for All Scopes
  ;; ---------------------------------------------------------------------------

  (test-case "memory protection round-trip with same-process scope"
    (define original #"0123456789abcdef")
    (define data (bytes-copy original))
    (protect-memory! data #:scope 'same-process)
    (check-false (equal? data original) "data should be encrypted")
    (unprotect-memory! data #:scope 'same-process)
    (check-equal? data original "data should match after decryption"))

  (test-case "memory protection round-trip with cross-process scope"
    (define original #"cross-process!!!")  ; 16 bytes
    (define data (bytes-copy original))
    (protect-memory! data #:scope 'cross-process)
    (check-false (equal? data original))
    (unprotect-memory! data #:scope 'cross-process)
    (check-equal? data original))

  (test-case "memory protection round-trip with same-logon scope"
    (define original #"same-logon-data!")  ; 16 bytes
    (define data (bytes-copy original))
    (protect-memory! data #:scope 'same-logon)
    (check-false (equal? data original))
    (unprotect-memory! data #:scope 'same-logon)
    (check-equal? data original))

  ;; ---------------------------------------------------------------------------
  ;; Multi-Block Data
  ;; ---------------------------------------------------------------------------

  (test-case "memory protection with multiple blocks"
    (define original (make-bytes 64 #xAB))
    (define data (bytes-copy original))
    (protect-memory! data)
    (check-false (equal? data original))
    (unprotect-memory! data)
    (check-equal? data original))

  (test-case "memory protection with large aligned buffer"
    (define original (make-bytes 256 #x42))
    (define data (bytes-copy original))
    (protect-memory! data)
    (unprotect-memory! data)
    (check-equal? data original))

  ;; ---------------------------------------------------------------------------
  ;; Encrypted Data Differs from Original
  ;; ---------------------------------------------------------------------------

  (test-case "encrypted memory differs from original"
    (define data (make-bytes 16 #xFF))
    (define original (bytes-copy data))
    (protect-memory! data)
    (check-false (equal? data original)
                 "in-place encryption should change the buffer contents"))

  (test-case "protect-memory! returns void"
    (define data (make-bytes 16 0))
    (check-equal? (protect-memory! data) (void)))

  ;; ---------------------------------------------------------------------------
  ;; Protected Value API
  ;; ---------------------------------------------------------------------------

  (test-case "protected-value round-trip"
    (define pv (make-protected-value #"my secret"))
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-copy data))))
    (check-equal? result #"my secret")
    (destroy-protected-value! pv))

  (test-case "protected-value with various data sizes"
    (for ([size (in-list '(1 15 16 17 31 32 100))])
      (define data (make-bytes size (modulo size 256)))
      (define pv (make-protected-value data))
      (define result
        (with-decrypted-data pv (lambda (d) (bytes-copy d))))
      (check-equal? result data
                    (format "failed for size ~a" size))
      (destroy-protected-value! pv)))

  (test-case "protected-value destruction prevents further access"
    (define pv (make-protected-value #"to be destroyed"))
    (destroy-protected-value! pv)
    (check-exn exn:fail?
      (lambda () (with-decrypted-data pv (lambda (d) d)))))

  (test-case "protected-value re-encrypts after exception in callback"
    (define pv (make-protected-value #"exception test"))
    ;; Throw an exception during with-decrypted-data
    (with-handlers ([exn:fail? void])
      (with-decrypted-data pv (lambda (data) (error "boom"))))
    ;; Should still work after the exception
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-copy data))))
    (check-equal? result #"exception test")
    (destroy-protected-value! pv))

  (test-case "nested with-decrypted-data on the same value raises instead of deadlocking"
    (define pv (make-protected-value #"nested test"))
    (check-exn #rx"nested call"
      (lambda ()
        (with-decrypted-data pv
          (lambda (outer)
            (with-decrypted-data pv (lambda (inner) inner))))))
    (check-exn #rx"nested call"
      (lambda ()
        (with-decrypted-data pv
          (lambda (outer) (destroy-protected-value! pv)))))
    ;; Value is re-encrypted and usable after the failed nested calls
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-copy data))))
    (check-equal? result #"nested test")
    (destroy-protected-value! pv))

  (test-case "nested access to a different value is allowed"
    (define pv1 (make-protected-value #"first"))
    (define pv2 (make-protected-value #"second"))
    (define result
      (with-decrypted-data pv1
        (lambda (d1)
          (with-decrypted-data pv2
            (lambda (d2) (bytes-append d1 d2))))))
    (check-equal? result #"firstsecond")
    (destroy-protected-value! pv1)
    (destroy-protected-value! pv2))

  (test-case "protected-value with cross-process scope"
    (define pv (make-protected-value #"cross-proc" #:scope 'cross-process))
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-copy data))))
    (check-equal? result #"cross-proc")
    (destroy-protected-value! pv))

  (test-case "protected-value with same-logon scope"
    (define pv (make-protected-value #"logon-data" #:scope 'same-logon))
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-copy data))))
    (check-equal? result #"logon-data")
    (destroy-protected-value! pv))

  (test-case "protected-value callback return value is propagated"
    (define pv (make-protected-value #"test"))
    (define result
      (with-decrypted-data pv (lambda (data) (bytes-length data))))
    (check-equal? result 4)
    (destroy-protected-value! pv))

  (test-case "protected-value multiple accesses"
    (define pv (make-protected-value #"multi-access"))
    (for ([_ (in-range 5)])
      (define result
        (with-decrypted-data pv (lambda (data) (bytes-copy data))))
      (check-equal? result #"multi-access"))
    (destroy-protected-value! pv)))
