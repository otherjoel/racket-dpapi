#lang racket/base

;; Low-level FFI bindings to Windows DPAPI (crypt32.dll and kernel32.dll)

(require ffi/unsafe)

(provide dpapi-available?
         make-DATA_BLOB
         DATA_BLOB-cbData
         DATA_BLOB-pbData
         CRYPTPROTECT_UI_FORBIDDEN
         CRYPTPROTECT_LOCAL_MACHINE
         CRYPTPROTECT_AUDIT
         CRYPTPROTECTMEMORY_SAME_PROCESS
         CRYPTPROTECTMEMORY_CROSS_PROCESS
         CRYPTPROTECTMEMORY_SAME_LOGON
         CRYPTPROTECTMEMORY_BLOCK_SIZE
         CryptProtectData
         CryptUnprotectData
         CryptProtectMemory
         CryptUnprotectMemory
         LocalFree)

;; =============================================================================
;; Library Loading
;; =============================================================================

(define crypt32-lib
  (with-handlers ([exn:fail? (lambda (e) #f)])
    (ffi-lib "crypt32")))

(define kernel32-lib
  (with-handlers ([exn:fail? (lambda (e) #f)])
    (ffi-lib "kernel32")))

(define (dpapi-available?)
  (and crypt32-lib kernel32-lib #t))

;; =============================================================================
;; C Type Definitions
;; =============================================================================

(define _DWORD _uint32)
(define _BOOL _int32)
(define _PVOID _pointer)

;; Wide string pointer (UTF-16) - can be NULL
(define _LPCWSTR (_or-null _pointer))

;; Output wide string pointer (nullable for optional use)
(define _LPWSTR* (_or-null (_ptr o _pointer)))

;; DATA_BLOB structure
;; typedef struct _DATA_BLOB {
;;   DWORD cbData;
;;   BYTE  *pbData;
;; } DATA_BLOB;
(define-cstruct _DATA_BLOB
  ([cbData _DWORD]
   [pbData _pointer]))

;; =============================================================================
;; Constants
;; =============================================================================

;; CryptProtectData / CryptUnprotectData flags
(define CRYPTPROTECT_UI_FORBIDDEN #x1)
(define CRYPTPROTECT_LOCAL_MACHINE #x4)
(define CRYPTPROTECT_AUDIT #x10)

;; CryptProtectMemory / CryptUnprotectMemory flags
(define CRYPTPROTECTMEMORY_SAME_PROCESS #x0)
(define CRYPTPROTECTMEMORY_CROSS_PROCESS #x1)
(define CRYPTPROTECTMEMORY_SAME_LOGON #x2)
(define CRYPTPROTECTMEMORY_BLOCK_SIZE 16)

;; =============================================================================
;; Function Bindings
;; =============================================================================

;; CryptProtectData
;; BOOL CryptProtectData(
;;   DATA_BLOB *pDataIn,
;;   LPCWSTR szDataDescr,
;;   DATA_BLOB *pOptionalEntropy,
;;   PVOID pvReserved,
;;   CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
;;   DWORD dwFlags,
;;   DATA_BLOB *pDataOut
;; );
(define CryptProtectData
  (and crypt32-lib
       (get-ffi-obj "CryptProtectData" crypt32-lib
                    (_fun #:save-errno 'windows
                          _DATA_BLOB-pointer       ; pDataIn
                          _LPCWSTR                 ; szDataDescr
                          _DATA_BLOB-pointer/null  ; pOptionalEntropy (can be NULL)
                          _PVOID                   ; pvReserved (must be NULL)
                          _pointer                 ; pPromptStruct (must be NULL)
                          _DWORD                   ; dwFlags
                          _DATA_BLOB-pointer       ; pDataOut
                          -> _BOOL)
                    (lambda () #f))))

;; CryptUnprotectData
;; BOOL CryptUnprotectData(
;;   DATA_BLOB *pDataIn,
;;   LPWSTR *ppszDataDescr,
;;   DATA_BLOB *pOptionalEntropy,
;;   PVOID pvReserved,
;;   CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
;;   DWORD dwFlags,
;;   DATA_BLOB *pDataOut
;; );
(define CryptUnprotectData
  (and crypt32-lib
       (get-ffi-obj "CryptUnprotectData" crypt32-lib
                    (_fun #:save-errno 'windows
                          _DATA_BLOB-pointer       ; pDataIn
                          _LPWSTR*                 ; ppszDataDescr
                          _DATA_BLOB-pointer/null  ; pOptionalEntropy (can be NULL)
                          _PVOID                   ; pvReserved (must be NULL)
                          _pointer                 ; pPromptStruct (must be NULL)
                          _DWORD                   ; dwFlags
                          _DATA_BLOB-pointer       ; pDataOut
                          -> _BOOL)
                    (lambda () #f))))

;; CryptProtectMemory
;; BOOL CryptProtectMemory(
;;   LPVOID pDataIn,
;;   DWORD cbDataIn,
;;   DWORD dwFlags
;; );
(define CryptProtectMemory
  (and crypt32-lib
       (get-ffi-obj "CryptProtectMemory" crypt32-lib
                    (_fun #:save-errno 'windows
                          _pointer  ; pDataIn
                          _DWORD    ; cbDataIn
                          _DWORD    ; dwFlags
                          -> _BOOL)
                    (lambda () #f))))

;; CryptUnprotectMemory
;; BOOL CryptUnprotectMemory(
;;   LPVOID pDataIn,
;;   DWORD cbDataIn,
;;   DWORD dwFlags
;; );
(define CryptUnprotectMemory
  (and crypt32-lib
       (get-ffi-obj "CryptUnprotectMemory" crypt32-lib
                    (_fun #:save-errno 'windows
                          _pointer  ; pDataIn
                          _DWORD    ; cbDataIn
                          _DWORD    ; dwFlags
                          -> _BOOL)
                    (lambda () #f))))

;; LocalFree
;; HLOCAL LocalFree(HLOCAL hMem);
(define LocalFree
  (and kernel32-lib
       (get-ffi-obj "LocalFree" kernel32-lib
                    (_fun _pointer -> _pointer)
                    (lambda () #f))))
