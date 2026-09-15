#lang racket/base

;; CryptProtectData and CryptUnprotectData implementation

(require ffi/unsafe
         "ffi.rkt"
         "errors.rkt")

(provide protect-data
         unprotect-data)

;; =============================================================================
;; UTF-16LE String Conversion
;; =============================================================================

(define (string->utf16le-ptr str)
  ;; Convert Racket string to UTF-16LE pointer
  ;; Use cast to convert string to wide string pointer
  (cast str _string/utf-16 _pointer))

(define (utf16le-ptr->string ptr)
  ;; Convert UTF-16LE pointer to Racket string
  (and ptr (cast ptr _pointer _string/utf-16)))

;; =============================================================================
;; DATA_BLOB Helper Functions
;; =============================================================================

(define (bytes->data-blob data)
  ;; Convert Racket bytes to DATA_BLOB pointer
  (if (not data)
      #f
      (let* ([len (bytes-length data)]
             [data-ptr (malloc len 'atomic-interior)])
        (memcpy data-ptr data len _byte)
        (make-DATA_BLOB len data-ptr))))

(define (data-blob->bytes blob)
  ;; Extract bytes from DATA_BLOB and copy to Racket bytes
  (let* ([size (DATA_BLOB-cbData blob)]
         [data-ptr (DATA_BLOB-pbData blob)]
         [result (make-bytes size)])
    (memcpy result 0 data-ptr size _byte)
    result))

(define (zero-data-blob! blob)
  ;; Zero out the data in a DATA_BLOB (best-effort scrub of sensitive data)
  (when (and blob (DATA_BLOB-pbData blob))
    (memset (DATA_BLOB-pbData blob) 0 (DATA_BLOB-cbData blob) _byte)))

(define (free-data-blob-contents blob)
  ;; Free the pbData pointer using LocalFree (allocated by Windows)
  (when (and blob (DATA_BLOB-pbData blob))
    (LocalFree (DATA_BLOB-pbData blob))))

;; =============================================================================
;; Data Protection Functions
;; =============================================================================

(define (protect-data data
                      #:description [description #f]
                      #:entropy [entropy #f]
                      #:machine-scope? [machine-scope? #f]
                      #:audit? [audit? #f])
  ;; Encrypt data using CryptProtectData
  (unless (dpapi-available?)
    (error 'protect-data "DPAPI not available on this platform"))

  ;; Convert inputs to C types
  (define data-blob (bytes->data-blob data))
  (define entropy-blob (and entropy (bytes->data-blob entropy)))
  (define desc-ptr (and description (string->utf16le-ptr description)))

  ;; Build flags
  (define flags
    (bitwise-ior CRYPTPROTECT_UI_FORBIDDEN
                 (if machine-scope? CRYPTPROTECT_LOCAL_MACHINE 0)
                 (if audit? CRYPTPROTECT_AUDIT 0)))

  ;; Allocate output blob (Windows will fill in the fields)
  (define out-blob (make-DATA_BLOB 0 #f))

  ;; Call CryptProtectData
  (define result
    (CryptProtectData data-blob
                      desc-ptr
                      entropy-blob
                      #f  ; pvReserved
                      #f  ; pPromptStruct
                      flags
                      out-blob))

  ;; Zero sensitive inputs regardless of success/failure
  (zero-data-blob! data-blob)
  (when entropy-blob (zero-data-blob! entropy-blob))

  ;; Check result and handle errors
  (if (zero? result)
      (raise-dpapi-error (saved-errno) "CryptProtectData failed")
      (begin0
        (data-blob->bytes out-blob)
        ;; Free memory allocated by Windows
        (free-data-blob-contents out-blob))))

(define (unprotect-data encrypted-data
                        #:entropy [entropy #f]
                        #:return-description? [return-description? #f])
  ;; Decrypt data using CryptUnprotectData
  (unless (dpapi-available?)
    (error 'unprotect-data "DPAPI not available on this platform"))

  ;; Convert inputs to C types
  (define data-blob (bytes->data-blob encrypted-data))
  (define entropy-blob (and entropy (bytes->data-blob entropy)))

  ;; Allocate output blob (Windows will fill in the fields) and description pointer
  (define out-blob (make-DATA_BLOB 0 #f))
  (define desc-ptr-box (malloc _pointer 'atomic-interior))
  (ptr-set! desc-ptr-box _pointer #f)

  ;; Always include UI_FORBIDDEN flag
  (define flags CRYPTPROTECT_UI_FORBIDDEN)

  ;; Call CryptUnprotectData
  (define result
    (CryptUnprotectData data-blob
                        (if return-description? desc-ptr-box #f)
                        entropy-blob
                        #f  ; pvReserved
                        #f  ; pPromptStruct
                        flags
                        out-blob))

  ;; Zero entropy regardless of success/failure
  (when entropy-blob (zero-data-blob! entropy-blob))

  ;; Check result
  (when (zero? result)
    (raise-dpapi-error (saved-errno) "CryptUnprotectData failed"))

  ;; Extract results; ensure Windows-allocated buffers are zeroed and freed
  ;; even if extraction raises an exception
  (define decrypted-data #f)
  (define desc #f)
  (dynamic-wind
    void
    (lambda ()
      (set! decrypted-data (data-blob->bytes out-blob))
      (set! desc (and return-description?
                      (let ([ptr (ptr-ref desc-ptr-box _pointer)])
                        (and ptr (utf16le-ptr->string ptr))))))
    (lambda ()
      (zero-data-blob! out-blob)
      (free-data-blob-contents out-blob)
      (when return-description?
        (let ([ptr (ptr-ref desc-ptr-box _pointer)])
          (when ptr (LocalFree ptr))))))

  (if return-description?
      (values decrypted-data desc)
      decrypted-data))
