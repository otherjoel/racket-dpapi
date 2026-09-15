#lang scribble/manual
@require[@for-label[dpapi
                    racket/base
                    racket/contract]]

@title[#:tag "reference"]{API Reference}

@section{Platform Detection}

@defproc[(dpapi-available?) boolean?]{
 Returns @racket[#t] if DPAPI is available on the current platform, @racket[#f] otherwise.

 On Windows Vista or later, this returns @racket[#t]. On all other platforms (Linux, macOS, etc.),
 it returns @racket[#f].

 @racketblock[
 (if (dpapi-available?)
     (displayln "DPAPI is available")
     (displayln "DPAPI is not available"))
 ]
}

@section[#:tag "ref-protected-values"]{Protected Values}

A @deftech{protected value} is an opaque wrapper that keeps sensitive data encrypted in memory
using @hyperlink["https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectmemory"]{CryptProtectMemory}.
The only way to access the plaintext is through @racket[with-decrypted-data], which temporarily
decrypts the data for the duration of a callback and automatically re-encrypts afterward.

@defproc[(make-protected-value [data bytes?]
                               [#:scope scope (or/c 'same-process 'cross-process 'same-logon) 'same-process]
                               [#:description description (or/c string? #f) #f])
         protected-value?]{

Creates a @tech{protected value} with @racket[data] immediately encrypted in memory.

The data is automatically padded to 16-byte blocks and encrypted. Returns an opaque
struct that can only be accessed through @racket[with-decrypted-data].

The @racket[scope] parameter controls which processes can decrypt the in-memory representation:

@itemlist[#:style 'compact
  @item{@racket['same-process]: Only this process can decrypt}
  @item{@racket['cross-process]: Any process on this machine can decrypt}
  @item{@racket['same-logon]: Any process by the same logged-in user can decrypt}
]

The @racket[description] is an optional label stored in the @tech{protected value}. It is used
as the default description when exporting with @racket[export-protected-bytes], and can be
retrieved with @racket[protected-value-description].

Example:

@racketblock[
(define password
  (make-protected-value (string->bytes/utf-8 "secret")
                        #:description "User Password"))
]

}

@defproc[(with-decrypted-data [pv protected-value?]
                              [proc (-> bytes? any)])
         any]{

Temporarily decrypts the bytes inside @racket[pv], calls @racket[proc] with the decrypted (unpadded)
data, then automatically re-encrypts before returning.

The data is only exposed during the dynamic extent of the callback. The protected value is always
re-encrypted, even if @racket[proc] throws an exception.

This is the only way to access the data inside a @tech{protected value}. Raises @racket[exn:fail]
if @racket[pv] has been destroyed with @racket[destroy-protected-value!].

Access to a @tech{protected value} is exclusive and not re-entrant. While @racket[proc] is running,
other threads that call @racket[with-decrypted-data], @racket[export-protected-bytes], or
@racket[destroy-protected-value!] on the same value block until @racket[proc] returns. Calling any of
those on the same value from within @racket[proc] on the same thread raises @racket[exn:fail]
rather than deadlocking.

If the thread running @racket[proc] is terminated with @racket[kill-thread], the cleanup that
re-encrypts and zeros the data does not run. The plaintext remains in memory, and the value stays
locked, so any later call on it blocks indefinitely (a blocked caller can still be interrupted with
@racket[break-thread]). Use @racket[break-thread] rather than @racket[kill-thread] to interrupt a
callback; breaks unwind normally and the value is re-encrypted.

Example:

@racketblock[
(with-decrypted-data password
  (lambda (pwd-bytes)
    (connect-to-database (bytes->string/utf-8 pwd-bytes))))
]
}

@defproc[(destroy-protected-value! [pv protected-value?]) void?]{
Zeros out the encrypted data and marks the protected value as destroyed. Any subsequent
call to @racket[with-decrypted-data] on this value will raise @racket[exn:fail].

This is a best-effort attempt to remove sensitive data from memory. Racket's garbage
collector may have already copied the data elsewhere.

Example:

@racketblock[
(destroy-protected-value! password)
]
}

@defproc[(protected-value? [v any/c]) boolean?]{
Returns @racket[#t] if @racket[v] is a @tech{protected value}, @racket[#f] otherwise.
}

@defproc[(protected-value-description [pv protected-value?]) (or/c string? #f)]{
Returns the description associated with @racket[pv], or @racket[#f] if none was provided.

When a @tech{protected value} is created by @racket[import-protected-bytes], the description
stored in the DPAPI blob is automatically captured here.
}

@section[#:tag "ref-disk-persistence"]{Disk Persistence}

These functions bridge between @tech{protected values} (in-memory) and DPAPI-encrypted bytes
suitable for writing to disk, using
@hyperlink["https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata"]{CryptProtectData}
and
@hyperlink["https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata"]{CryptUnprotectData}
internally. The plaintext is never exposed to calling code---it is decrypted and re-encrypted
internally.

@defproc[(export-protected-bytes [pv protected-value?]
                                  [#:description description (or/c string? #f) #f]
                                  [#:entropy entropy (or/c bytes? #f) #f]
                                  [#:machine-scope? machine-scope? boolean? #f]
                                  [#:audit? audit? boolean? #f])
         bytes?]{

Exports the contents of @racket[pv] as DPAPI-encrypted bytes suitable for persistent storage (files,
databases, etc.). The returned bytes are encrypted using Windows credentials and can be imported
back with @racket[import-protected-bytes]. Raises @racket[exn:fail:dpapi] if encryption fails, and
@racket[exn:fail] if DPAPI is not available or the protected value has been destroyed.

If @racket[description] is not provided, the description from @racket[pv] (see
@racket[protected-value-description]) is used. If explicitly provided, it overrides the
@tech{protected value}'s description. Either way, a non-@racket[#f] description is stored
unencrypted alongside the encrypted data, where it will be captured by
@racket[import-protected-bytes].

 If @racket[entropy] is not @racket[#f], it is used as a factor in the encryption of the exported
 bytes. An attempt to re-import the resulting bytes without identical entropy will fail with an
 exception.
 
 If @racket[machine-scope?] is @racket[#t], the resulting bytes will be decryptable by other users
 on the same machine.
 
 If @racket[audit?] is @racket[#t], Windows will generate audit log entries for the operation (but 
 only if @racket[description] is provided as a non-empty string).

 Example:

@racketblock[
(define encrypted-bytes
  (export-protected-bytes password
                          #:entropy (string->bytes/utf-8 "app-secret")
                          #:description "User Password"))

(code:comment2 "Write to disk")
(with-output-to-file "password.encrypted"
  (lambda () (write-bytes encrypted-bytes))
  #:exists 'replace)
]
}

@defproc[(import-protected-bytes [encrypted-data bytes?]
                                  [#:entropy entropy (or/c bytes? #f) #f]
                                  [#:scope scope (or/c 'same-process 'cross-process 'same-logon) 'same-process])
         protected-value?]{

Imports DPAPI-encrypted bytes (previously created by @racket[export-protected-bytes]) and returns a
@tech{protected value}. The plaintext is decrypted from the DPAPI format and immediately
re-encrypted in memory---it is never returned directly. Raises @racket[exn:fail:dpapi] if decryption
fails (wrong entropy, corrupted data, wrong user/machine, etc.).

If a description was stored in the DPAPI blob, it is automatically captured in the returned
@tech{protected value} and can be retrieved with @racket[protected-value-description].

The @racket[entropy] must match the value used during export.

The @racket[scope] parameter sets the memory protection scope for the resulting protected
value (see @racket[make-protected-value]).



@racketblock[
(code:comment "Read from disk")
(define encrypted-bytes (file->bytes "password.encrypted"))

(code:comment "Import into a protected value")
(define password
  (import-protected-bytes encrypted-bytes
                          #:entropy (string->bytes/utf-8 "app-secret")))

(code:comment "Retrieve the description")
(protected-value-description password)
]
}

@section[#:tag "error-handling-reference"]{Error Handling}

@defstruct*[exn:fail:dpapi
            ([message string?]
             [continuation-marks continuation-mark-set?]
             [error-code exact-nonnegative-integer?]
             [error-message string?])
            #:transparent]{
Exception structure for DPAPI errors. Extends @racket[exn:fail]. This exception is raised only
when a Windows DPAPI call reports failure; local validation failures (DPAPI not available,
destroyed @tech{protected value}, malformed data) raise a plain @racket[exn:fail] instead.

@itemlist[
  @item{@racket[error-code]: Windows error code from @tt{GetLastError}}
  @item{@racket[error-message]: Human-readable description of the error}
]

The @racket[message] field contains both context and the error message.

@tabular[#:sep @hspace[2]
         #:column-properties '(left left)
         (list (list @bold{Error Code} @bold{Description})
               (list @racketvalfont{13} "ERROR_INVALID_DATA: Data is corrupted or invalid")
               (list @racketvalfont{14} "ERROR_OUTOFMEMORY: Not enough memory")
               (list @racketvalfont{50} "ERROR_NOT_SUPPORTED: Operation not supported on this OS")
               (list @racketvalfont{87} "ERROR_INVALID_PARAMETER: Invalid parameter")
               (list @racketvalfont{0x80090003} "NTE_BAD_KEY: Wrong entropy or protection scope")
               (list @racketvalfont{0x80090005} "NTE_BAD_DATA: Invalid encrypted data format"))]

}
