#lang racket/base

;; CryptProtectMemory and CryptUnprotectMemory implementation

(require ffi/unsafe
         "ffi.rkt"
         "errors.rkt")

(provide protect-memory!
         unprotect-memory!)

;; =============================================================================
;; Scope Mapping
;; =============================================================================

(define (scope->flag scope)
  ;; Map scope symbol to DPAPI flag
  (case scope
    [(same-process) CRYPTPROTECTMEMORY_SAME_PROCESS]
    [(cross-process) CRYPTPROTECTMEMORY_CROSS_PROCESS]
    [(same-logon) CRYPTPROTECTMEMORY_SAME_LOGON]
    [else (error 'scope->flag "invalid scope: ~a" scope)]))

;; =============================================================================
;; Memory Protection Functions
;; =============================================================================

(define (protect-memory! data #:scope [scope 'same-process])
  ;; Encrypt memory in-place using CryptProtectMemory
  (unless (dpapi-available?)
    (error 'protect-memory! "DPAPI not available on this platform"))

  (when (immutable? data)
    (error 'protect-memory! "data must be a mutable byte string"))

  (define len (bytes-length data))

  ;; Validate length is multiple of block size
  (unless (zero? (modulo len CRYPTPROTECTMEMORY_BLOCK_SIZE))
    (error 'protect-memory!
           "data length (~a) must be multiple of ~a"
           len
           CRYPTPROTECTMEMORY_BLOCK_SIZE))

  ;; Get scope flag
  (define flags (scope->flag scope))

  ;; Get pointer to bytes data
  (define data-ptr (cast data _bytes _pointer))

  ;; Call CryptProtectMemory (operates in-place)
  (define result (CryptProtectMemory data-ptr len flags))

  ;; Check result
  (when (zero? result)
    (raise-dpapi-error (saved-errno) "CryptProtectMemory failed"))

  ;; Return void (data is mutated in place)
  (void))

(define (unprotect-memory! encrypted-data #:scope [scope 'same-process])
  ;; Decrypt memory in-place using CryptUnprotectMemory
  (unless (dpapi-available?)
    (error 'unprotect-memory! "DPAPI not available on this platform"))

  (when (immutable? encrypted-data)
    (error 'unprotect-memory! "data must be a mutable byte string"))

  (define len (bytes-length encrypted-data))

  ;; Validate length is multiple of block size
  (unless (zero? (modulo len CRYPTPROTECTMEMORY_BLOCK_SIZE))
    (error 'unprotect-memory!
           "data length (~a) must be multiple of ~a"
           len
           CRYPTPROTECTMEMORY_BLOCK_SIZE))

  ;; Get scope flag (must match the scope used for encryption)
  (define flags (scope->flag scope))

  ;; Get pointer to bytes data
  (define data-ptr (cast encrypted-data _bytes _pointer))

  ;; Call CryptUnprotectMemory (operates in-place)
  (define result (CryptUnprotectMemory data-ptr len flags))

  ;; Check result
  (when (zero? result)
    (raise-dpapi-error (saved-errno) "CryptUnprotectMemory failed"))

  ;; Return void (data is mutated in place)
  (void))
