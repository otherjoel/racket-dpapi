#lang racket/base

;; High-level opaque protected value API for memory protection

(require "memory-protect.rkt"
         "utils.rkt"
         "errors.rkt"
         "data-protect.rkt")

(provide make-protected-value
         with-decrypted-data
         destroy-protected-value!
         protected-value?
         protected-value-description
         export-protected-bytes
         import-protected-bytes)

;; =============================================================================
;; Protected Value Structure (Opaque)
;; =============================================================================

;; Protected values are always encrypted in memory except during callback execution
;; The struct is opaque because we don't export the accessors
(struct protected-value (box scope sema description))

;; =============================================================================
;; Construction
;; =============================================================================

(define (make-protected-value data
                               #:scope [scope 'same-process]
                               #:description [description #f])
  (define padded (pad-to-block-size data))
  (protect-memory! padded #:scope scope)
  (protected-value (box padded) scope (make-semaphore 1) description))

;; =============================================================================
;; Controlled Access
;; =============================================================================

(define (with-decrypted-data pv proc)
  ;; Temporarily decrypt the protected value, call proc with the decrypted data,
  ;; then automatically re-encrypt before returning.
  ;; The data is only exposed during the dynamic extent of the callback.
  (call-with-semaphore (protected-value-sema pv)
    (lambda ()
      (define data-box (protected-value-box pv))
      (define scope (protected-value-scope pv))
      (define encrypted (unbox data-box))

      (unless encrypted
        (raise-dpapi-error 13 "with-decrypted-data: protected value has been destroyed"))

      ;; Decrypt in-place
      (unprotect-memory! encrypted #:scope scope)

      ;; Call proc with unpadded data, then re-encrypt even if proc throws.
      ;; dynamic-wind guarantees the post thunk runs even on exception or continuation jump.
      (define unpadded #f)
      (dynamic-wind
        void
        (lambda ()
          (set! unpadded (unpad-from-block-size encrypted))
          (proc unpadded))
        (lambda ()
          (when unpadded (zero-bytes! unpadded))
          (protect-memory! encrypted #:scope scope))))))

;; =============================================================================
;; Cleanup
;; =============================================================================

(define (destroy-protected-value! pv)
  ;; Zero out the protected memory before allowing it to be garbage collected.
  ;; This is a best-effort attempt to remove sensitive data from memory.
  ;; Note: Racket's GC may have already copied the data elsewhere.
  (call-with-semaphore (protected-value-sema pv)
    (lambda ()
      (define data-box (protected-value-box pv))
      (define encrypted (unbox data-box))
      (when encrypted
        (zero-bytes! encrypted)
        (set-box! data-box #f)))))

;; =============================================================================
;; Disk Persistence (DPAPI bridge)
;; =============================================================================

(define _no-description (gensym 'no-description))

(define (export-protected-bytes pv
                                #:description [description _no-description]
                                #:entropy [entropy #f]
                                #:machine-scope? [machine-scope? #f]
                                #:audit? [audit? #f])
  (define desc (if (eq? description _no-description)
                   (protected-value-description pv)
                   description))
  (with-decrypted-data pv
    (lambda (data)
      (protect-data data
                    #:description desc
                    #:entropy entropy
                    #:machine-scope? machine-scope?
                    #:audit? audit?))))

(define (import-protected-bytes encrypted-data
                                #:entropy [entropy #f]
                                #:scope [scope 'same-process])
  (let-values ([(decrypted desc)
                (unprotect-data encrypted-data
                                #:entropy entropy
                                #:return-description? #t)])
    (begin0
      (make-protected-value decrypted #:scope scope #:description desc)
      (zero-bytes! decrypted))))
