#lang racket/base

;; Error handling for DPAPI operations

(require racket/format)

(provide exn:fail:dpapi
         exn:fail:dpapi?
         exn:fail:dpapi-error-code
         exn:fail:dpapi-error-message
         raise-dpapi-error)

;; =============================================================================
;; Exception Structure
;; =============================================================================

(struct exn:fail:dpapi exn:fail (error-code error-message)
  #:transparent)

;; =============================================================================
;; Error Code Mapping
;; =============================================================================

(define error-code-table
  (hash
   ;; Common system error codes
   13  "ERROR_INVALID_DATA: The data is invalid or corrupted"
   14  "ERROR_OUTOFMEMORY: Not enough memory to complete operation"
   50  "ERROR_NOT_SUPPORTED: The request is not supported"
   87  "ERROR_INVALID_PARAMETER: A parameter is incorrect"

   ;; Cryptography error codes (NTE_* constants)
   #x80090003 "NTE_BAD_KEY: Bad key (wrong entropy or protection scope)"
   #x80090005 "NTE_BAD_DATA: Bad data (invalid encrypted data format)"
   #x80090008 "NTE_BAD_ALGID: Invalid algorithm specified"
   #x80090009 "NTE_BAD_FLAGS: Invalid flags specified"
   #x8009000D "NTE_NO_KEY: Key does not exist"
   #x80090016 "NTE_BAD_KEYSET: Keyset does not exist"
   #x80090020 "NTE_FAIL: Internal error occurred"))

(define (error-code->message code)
  (hash-ref error-code-table code
            (~a "Unknown error (code: " code ")")))

;; =============================================================================
;; Error Raising Function
;; =============================================================================

(define (raise-dpapi-error error-code [context #f])
  (define error-msg (error-code->message error-code))
  (define full-message
    (if context
        (~a context ": " error-msg)
        error-msg))
  (raise (exn:fail:dpapi full-message
                         (current-continuation-marks)
                         error-code
                         error-msg)))

