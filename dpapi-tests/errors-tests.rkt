#lang racket/base

(require rackunit
         dpapi/private/errors
         dpapi/private/memory-protect
         dpapi/main)

;; =============================================================================
;; exn:fail:dpapi Struct Tests
;; =============================================================================

(test-case "exn:fail:dpapi struct has correct fields"
  (define e (exn:fail:dpapi "test message"
                            (current-continuation-marks)
                            42
                            "the error message"))
  (check-true (exn:fail:dpapi? e))
  (check-true (exn:fail? e))
  (check-true (exn? e))
  (check-equal? (exn:fail:dpapi-error-code e) 42)
  (check-equal? (exn:fail:dpapi-error-message e) "the error message")
  (check-equal? (exn-message e) "test message"))

(test-case "exn:fail:dpapi is transparent"
  (define e (exn:fail:dpapi "msg" (current-continuation-marks) 0 "err"))
  ;; Transparent structs can be inspected
  (check-true (exn:fail:dpapi? e))
  (check-equal? (exn:fail:dpapi-error-code e) 0)
  (check-equal? (exn:fail:dpapi-error-message e) "err"))

;; =============================================================================
;; Error Code and Message Tests
;; =============================================================================

(test-case "raise-dpapi-error with ERROR_INVALID_PARAMETER (87)"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) 87)
          (regexp-match? #rx"INVALID_PARAMETER" (exn-message e))
          (regexp-match? #rx"INVALID_PARAMETER" (exn:fail:dpapi-error-message e))))
   (lambda () (raise-dpapi-error 87))))

(test-case "raise-dpapi-error with ERROR_INVALID_DATA (13)"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) 13)
          (regexp-match? #rx"INVALID_DATA" (exn-message e))))
   (lambda () (raise-dpapi-error 13))))

(test-case "raise-dpapi-error with ERROR_OUTOFMEMORY (14)"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) 14)
          (regexp-match? #rx"OUTOFMEMORY" (exn-message e))))
   (lambda () (raise-dpapi-error 14))))

(test-case "raise-dpapi-error with ERROR_NOT_SUPPORTED (50)"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) 50)
          (regexp-match? #rx"NOT_SUPPORTED" (exn-message e))))
   (lambda () (raise-dpapi-error 50))))

(test-case "raise-dpapi-error with NTE_BAD_DATA"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) #x80090005)
          (regexp-match? #rx"NTE_BAD_DATA" (exn-message e))))
   (lambda () (raise-dpapi-error #x80090005))))

(test-case "raise-dpapi-error with NTE_BAD_KEY"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) #x80090003)
          (regexp-match? #rx"NTE_BAD_KEY" (exn-message e))))
   (lambda () (raise-dpapi-error #x80090003))))

(test-case "raise-dpapi-error with NTE_BAD_ALGID"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) #x80090008)
          (regexp-match? #rx"NTE_BAD_ALGID" (exn-message e))))
   (lambda () (raise-dpapi-error #x80090008))))

(test-case "raise-dpapi-error with unknown error code"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (= (exn:fail:dpapi-error-code e) 99999)
          (regexp-match? #rx"Unknown error" (exn-message e))
          (regexp-match? #rx"99999" (exn-message e))))
   (lambda () (raise-dpapi-error 99999))))

(test-case "raise-dpapi-error includes context in message"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (regexp-match? #rx"my-context" (exn-message e))
          (regexp-match? #rx"INVALID_PARAMETER" (exn-message e))))
   (lambda () (raise-dpapi-error 87 "my-context"))))

(test-case "raise-dpapi-error without context has clean message"
  (check-exn
   (lambda (e)
     (and (exn:fail:dpapi? e)
          (regexp-match? #rx"^ERROR_INVALID_PARAMETER" (exn-message e))))
   (lambda () (raise-dpapi-error 87))))

;; =============================================================================
;; DPAPI-Dependent Error Condition Tests (require Windows)
;; =============================================================================

(unless (dpapi-available?)
  (eprintf "errors-tests.rkt: DPAPI-dependent tests skipped, DPAPI not available on this platform\n"))

(when (dpapi-available?)
  (test-case "import with wrong entropy raises exn:fail:dpapi"
    (define pv (make-protected-value #"secret data for entropy test"))
    (define entropy #"correct-entropy")
    (define wrong-entropy #"wrong-entropy-value")
    (define exported (export-protected-bytes pv #:entropy entropy))
    (check-exn exn:fail:dpapi?
      (lambda () (import-protected-bytes exported #:entropy wrong-entropy)))
    (destroy-protected-value! pv))

  (test-case "import without entropy when exported with entropy raises error"
    (define pv (make-protected-value #"more secret data"))
    (define entropy #"my-entropy-key")
    (define exported (export-protected-bytes pv #:entropy entropy))
    (check-exn exn:fail:dpapi?
      (lambda () (import-protected-bytes exported)))
    (destroy-protected-value! pv))

  (test-case "import corrupted data raises exn:fail:dpapi"
    (check-exn exn:fail:dpapi?
      (lambda () (import-protected-bytes (make-bytes 100 42)))))

  (test-case "protect-memory! with non-block-aligned size raises error"
    (check-exn exn:fail?
      (lambda () (protect-memory! (make-bytes 1 0))))
    (check-exn exn:fail?
      (lambda () (protect-memory! (make-bytes 15 0))))
    (check-exn exn:fail?
      (lambda () (protect-memory! (make-bytes 17 0)))))

  (test-case "unprotect-memory! with non-block-aligned size raises error"
    (check-exn exn:fail?
      (lambda () (unprotect-memory! (make-bytes 1 0))))
    (check-exn exn:fail?
      (lambda () (unprotect-memory! (make-bytes 7 0))))
    (check-exn exn:fail?
      (lambda () (unprotect-memory! (make-bytes 31 0)))))

  (test-case "unprotect-memory! with wrong scope produces wrong data or error"
    (define original #"0123456789abcdef")
    (define data (bytes-copy original))
    (protect-memory! data #:scope 'same-process)
    (check-false (equal? data original) "encrypted data should differ")
    ;; Wrong scope: either raises error or produces garbage
    (with-handlers ([exn:fail:dpapi? (lambda (e) 'error-raised)])
      (unprotect-memory! data #:scope 'same-logon)
      (check-false (equal? data original)
                   "wrong scope should not produce correct plaintext"))))
