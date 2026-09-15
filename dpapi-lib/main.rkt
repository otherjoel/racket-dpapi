#lang racket/base

;; Public API for DPAPI with contracts

(require racket/contract
         "private/ffi.rkt"
         "private/errors.rkt"
         "private/protected-value.rkt")

;; =============================================================================
;; Public API with Contracts
;; =============================================================================

(provide
 (contract-out
  ;; Platform detection
  [dpapi-available? (-> boolean?)]

  ;; Protected value API
  [make-protected-value
   (->* (bytes?)
        (#:scope (or/c 'same-process 'cross-process 'same-logon)
         #:description (or/c string? #f))
        protected-value?)]

  [with-decrypted-data
   (-> protected-value? (-> bytes? any) any)]

  [destroy-protected-value!
   (-> protected-value? void?)]

  ;; Disk persistence (DPAPI bridge)
  [export-protected-bytes
   (->* (protected-value?)
        (#:description (or/c string? #f)
         #:entropy (or/c bytes? #f)
         #:machine-scope? boolean?
         #:audit? boolean?)
        bytes?)]

  [import-protected-bytes
   (->* (bytes?)
        (#:entropy (or/c bytes? #f)
         #:scope (or/c 'same-process 'cross-process 'same-logon))
        protected-value?)]

  [protected-value-description
   (-> protected-value? (or/c string? #f))])

 ;; Exception structure
 exn:fail:dpapi
 exn:fail:dpapi?
 exn:fail:dpapi-error-code
 exn:fail:dpapi-error-message

 ;; Protected value predicate
 protected-value?)
