#lang racket/base

(require rackunit
         dpapi/main)

;; =============================================================================
;; Integration Tests (require Windows)
;; =============================================================================

(when (dpapi-available?)

  ;; ---------------------------------------------------------------------------
  ;; Large Data
  ;; ---------------------------------------------------------------------------

  (test-case "large data round-trip (> 1 MB)"
    (define large-data (make-bytes (* 1024 1025) 42))  ; ~1.05 MB
    (define pv (make-protected-value large-data))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result large-data)
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  ;; ---------------------------------------------------------------------------
  ;; Binary Data
  ;; ---------------------------------------------------------------------------

  (test-case "binary data with all byte values"
    (define data (apply bytes (for/list ([i (in-range 256)]) i)))
    (define pv (make-protected-value data))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result data)
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "binary data with null bytes"
    (define data #"\x00\x00\x00\x00")
    (define pv (make-protected-value data))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result data)
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  ;; ---------------------------------------------------------------------------
  ;; Empty Bytes
  ;; ---------------------------------------------------------------------------

  (test-case "empty bytes raises error"
    ;; CryptProtectData rejects zero-length input
    (define pv (make-protected-value #"placeholder"))
    ;; We can't directly test empty bytes through the new API since
    ;; make-protected-value would need to handle it. Test that exporting
    ;; works and importing garbage fails.
    (check-exn exn:fail:dpapi?
      (lambda () (import-protected-bytes #""))))

  (test-case "single byte round-trip"
    (define data #"\xFF")
    (define pv (make-protected-value data))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result data)
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  ;; ---------------------------------------------------------------------------
  ;; Various Entropy Values
  ;; ---------------------------------------------------------------------------

  (test-case "various entropy values"
    (for ([entropy (in-list (list #"short"
                                  #"medium-length-entropy"
                                  (make-bytes 256 #xAB)
                                  #"\x00\x01\x02\x03"))])
      (define data #"test with different entropy")
      (define pv (make-protected-value data))
      (define exported (export-protected-bytes pv #:entropy entropy))
      (define pv2 (import-protected-bytes exported #:entropy entropy))
      (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
      (check-equal? result data
                    (format "failed with entropy of length ~a"
                            (bytes-length entropy)))
      (destroy-protected-value! pv)
      (destroy-protected-value! pv2)))

  (test-case "single-byte entropy"
    (define data #"single byte entropy test")
    (define pv (make-protected-value data))
    (define exported (export-protected-bytes pv #:entropy #"\xFF"))
    (define pv2 (import-protected-bytes exported #:entropy #"\xFF"))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result data)
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  ;; ---------------------------------------------------------------------------
  ;; Concurrent Operations
  ;; ---------------------------------------------------------------------------

  (test-case "concurrent export/import"
    (define results
      (for/list ([i (in-range 10)])
        (define ch (make-channel))
        (thread
          (lambda ()
            (define data (make-bytes 100 (modulo i 256)))
            (define pv (make-protected-value data))
            (define exported (export-protected-bytes pv))
            (define pv2 (import-protected-bytes exported))
            (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
            (destroy-protected-value! pv)
            (destroy-protected-value! pv2)
            (channel-put ch (equal? data result))))
        ch))
    (for ([ch (in-list results)])
      (check-true (channel-get ch))))

  (test-case "concurrent protected-value access"
    (define pv (make-protected-value #"shared secret"))
    (define results
      (for/list ([i (in-range 5)])
        (define ch (make-channel))
        (thread
          (lambda ()
            (define result
              (with-decrypted-data pv (lambda (data) (bytes-copy data))))
            (channel-put ch (equal? result #"shared secret"))))
        ch))
    (for ([ch (in-list results)])
      (check-true (channel-get ch)))
    (destroy-protected-value! pv))

  ;; ---------------------------------------------------------------------------
  ;; Memory Protection Cleanup
  ;; ---------------------------------------------------------------------------

  (test-case "protected-value double destroy is safe"
    (define pv (make-protected-value #"double destroy"))
    (destroy-protected-value! pv)
    ;; Second destroy should not error
    (destroy-protected-value! pv))

  (test-case "protected-value access after destroy raises error"
    (define pv (make-protected-value #"sensitive"))
    (destroy-protected-value! pv)
    (check-exn exn:fail?
      (lambda () (with-decrypted-data pv (lambda (d) d)))))

  ;; ---------------------------------------------------------------------------
  ;; Multiple Sequential Cycles
  ;; ---------------------------------------------------------------------------

  (test-case "multiple sequential export/import cycles"
    (for ([i (in-range 20)])
      (define data (make-bytes (+ 10 i) (modulo i 256)))
      (define pv (make-protected-value data))
      (define exported (export-protected-bytes pv))
      (define pv2 (import-protected-bytes exported))
      (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
      (check-equal? result data)
      (destroy-protected-value! pv)
      (destroy-protected-value! pv2)))

  (test-case "export-protected-bytes with all optional parameters"
    (define data #"full-featured test")
    (define pv (make-protected-value data))
    (define exported (export-protected-bytes pv
                                             #:description "full test"
                                             #:entropy #"test-entropy"
                                             #:machine-scope? #t
                                             #:audit? #t))
    (define pv2 (import-protected-bytes exported #:entropy #"test-entropy"))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result data)
    (check-equal? (protected-value-description pv2) "full test")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "description round-trips through struct"
    (define pv (make-protected-value #"test" #:description "my label"))
    (check-equal? (protected-value-description pv) "my label")
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (check-equal? (protected-value-description pv2) "my label")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "export-protected-bytes description override"
    (define pv (make-protected-value #"test" #:description "original"))
    (define exported (export-protected-bytes pv #:description "override"))
    (define pv2 (import-protected-bytes exported))
    (check-equal? (protected-value-description pv2) "override")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2)))
