#lang racket/base

(require rackunit
         dpapi/main)

;; =============================================================================
;; Platform Detection Tests
;; =============================================================================

(test-case "dpapi-available? returns boolean"
  (check-true (boolean? (dpapi-available?))))

(test-case "dpapi-available? returns #t on Windows"
  (when (eq? (system-type 'os) 'windows)
    (check-true (dpapi-available?))))

(test-case "dpapi-available? returns #f on non-Windows"
  (unless (eq? (system-type 'os) 'windows)
    (check-false (dpapi-available?))))

;; =============================================================================
;; Export/Import Round-Trip Tests (require Windows)
;; =============================================================================

(when (dpapi-available?)
  (test-case "basic round-trip export/import"
    (define pv (make-protected-value #"Hello, DPAPI!"))
    (define exported (export-protected-bytes pv))
    (check-true (bytes? exported))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"Hello, DPAPI!")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip with description"
    (define pv (make-protected-value #"data with description"))
    (define exported (export-protected-bytes pv #:description "test description"))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"data with description")
    (check-equal? (protected-value-description pv2) "test description")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip with entropy"
    (define pv (make-protected-value #"data with entropy"))
    (define entropy #"my-secret-entropy")
    (define exported (export-protected-bytes pv #:entropy entropy))
    (define pv2 (import-protected-bytes exported #:entropy entropy))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"data with entropy")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip with both description and entropy"
    (define pv (make-protected-value #"data with both"))
    (define entropy #"entropy-value")
    (define exported (export-protected-bytes pv
                                             #:description "desc"
                                             #:entropy entropy))
    (define pv2 (import-protected-bytes exported #:entropy entropy))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"data with both")
    (check-equal? (protected-value-description pv2) "desc")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip with machine scope"
    (define pv (make-protected-value #"machine-scoped data"))
    (define exported (export-protected-bytes pv #:machine-scope? #t))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"machine-scoped data")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip with audit flag"
    (define pv (make-protected-value #"audited data"))
    (define exported (export-protected-bytes pv #:audit? #t))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"audited data")
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "round-trip without description returns #f for description"
    (define pv (make-protected-value #"no desc"))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (define result (with-decrypted-data pv2 (lambda (d) (bytes-copy d))))
    (check-equal? result #"no desc")
    (define desc (protected-value-description pv2))
    (check-true (or (not desc) (equal? desc "")))
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2))

  (test-case "exported bytes differ between calls"
    (define pv (make-protected-value #"same data twice"))
    (define enc1 (export-protected-bytes pv))
    (define enc2 (export-protected-bytes pv))
    ;; DPAPI uses random salt, so exports should differ
    (check-false (equal? enc1 enc2))
    (destroy-protected-value! pv))

  (test-case "export-protected-bytes returns bytes"
    (define pv (make-protected-value #"test"))
    (check-true (bytes? (export-protected-bytes pv)))
    (destroy-protected-value! pv))

  (test-case "import-protected-bytes returns protected-value"
    (define pv (make-protected-value #"test"))
    (define exported (export-protected-bytes pv))
    (define pv2 (import-protected-bytes exported))
    (check-true (protected-value? pv2))
    (destroy-protected-value! pv)
    (destroy-protected-value! pv2)))
