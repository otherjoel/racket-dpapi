#lang scribble/manual

@require[scribble/example
         @for-label[dpapi
                    racket/base
                    racket/file
                    json]]

@require["doc-util.rkt"]

@;; The transcripts below use eval:alts with literal results captured from a real Windows session,
@;; so the documentation builds identically on platforms where DPAPI is unavailable.
@(define ev (make-base-eval #:lang 'racket/base))

@title[#:tag "getting-started"]{Getting Started}

This guide walks through common usage patterns for the DPAPI library.

@section{Installation}

Install from the Racket package catalog:

@terminal{
 @:>{raco pkg install dpapi}
}

Then require it in your Racket programs:

@racketblock[
(require dpapi)
]

@section{Protecting Data in Memory}

@inline-note[#:type 'warning]{Security is complicated! Be sure and read
@secref["security-best-practices"] before relying on this library for anything important.}

The core abstraction is the @tech{protected value}, which keeps sensitive data encrypted in memory.
Creating one encrypts a copy of the bytes you pass in; the result is an opaque value that does not
reveal its contents when printed:

@examples[#:eval ev #:label #f
  (eval:alts (require dpapi) (void))
  (eval:alts (dpapi-available?) (eval:result @racketresult[#t]))
  (eval:alts (define password
               (make-protected-value (string->bytes/utf-8 "my-secret-password")))
             (void))
  (eval:alts password (eval:result @racketresultfont{#<protected-value>}))
]

The only way to access the plaintext is through a callback passed to @racket[with-decrypted-data].
The callback receives the decrypted bytes, and the value is re-encrypted as soon as the callback
returns, even if it raises an exception. In practice the callback would do the real work, such as
opening a database connection, and return only what the rest of the program needs:

@examples[#:eval ev #:label #f
  (eval:alts (with-decrypted-data password
               (lambda (pwd-bytes)
                 (bytes-length pwd-bytes)))
             (eval:result @racketresult[18]))
]

When a protected value is no longer needed, destroy it. This zeros the encrypted buffer, and any
later attempt to use the value raises an error:

@examples[#:eval ev #:label #f
  (eval:alts (destroy-protected-value! password) (void))
  (eval:alts (with-decrypted-data password
               (lambda (pwd-bytes)
                 (bytes-length pwd-bytes)))
             (eval:result "" "" "with-decrypted-data: protected value has been destroyed"))
]

Note that @racket[make-protected-value] encrypts a @emph{copy} of the bytes you pass in. The
original byte string is left untouched, so in the example above the plaintext password also
remains in memory until it is garbage collected. See @secref["security-best-practices"] for how to
zero it yourself.

@section{Saving and Loading Encrypted Data}

A @tech{protected value} is not suitable for writing to permanent storage, because it is generally
scoped only to the currently running process.

The @racket[export-protected-bytes] and @racket[import-protected-bytes] functions convert between
in-memory protected values and DPAPI-encrypted values that can be used across sessions, without
exposing the plaintext to the rest of your code. The exported bytes are an opaque DPAPI blob that
can be written to disk as-is:

@examples[#:eval ev #:label #f
  (eval:alts (require racket/file) (void))
  (eval:alts (define token (make-protected-value #"oauth-token-value")) (void))
  (eval:alts (define encrypted-bytes
               (export-protected-bytes token
                                       #:entropy (string->bytes/utf-8 "app-v1-secret")
                                       #:description "OAuth Token"))
             (void))
  (eval:alts encrypted-bytes
             (eval:result @racketresultfont{#"\1\0\0\0\320\214\235\337\1\25\321\21\214z\0\300O\302\227\353\1\0\0\0"…}))
  (eval:alts (bytes-length encrypted-bytes) (eval:result @racketresult[268]))
  (eval:alts (display-to-file encrypted-bytes "token.encrypted" #:exists 'replace) (void))
]

Later, possibly in another process, read the file back and import it. The result is a new
@tech{protected value}, and the description stored alongside the encrypted data is available
through @racket[protected-value-description]:

@examples[#:eval ev #:label #f
  (eval:alts (define loaded-token
               (import-protected-bytes (file->bytes "token.encrypted")
                                       #:entropy (string->bytes/utf-8 "app-v1-secret")))
             (void))
  (eval:alts loaded-token (eval:result @racketresultfont{#<protected-value>}))
  (eval:alts (protected-value-description loaded-token) (eval:result @racketresult["OAuth Token"]))
  (eval:alts (with-decrypted-data loaded-token
               (lambda (token-bytes)
                 (bytes-length token-bytes)))
             (eval:result @racketresult[17]))
]

@subsection{Entropy}

The optional @racket[#:entropy] parameter on @racket[export-protected-bytes] and
@racket[import-protected-bytes] adds a secondary secret. Without the correct entropy,
decryption will fail even for the same Windows user. The same entropy must be provided
for both export and import. A mismatch, or omitting the entropy on import, raises
@racket[exn:fail:dpapi]:

@examples[#:eval ev #:label #f
  (eval:alts (import-protected-bytes (file->bytes "token.encrypted")
                                     #:entropy (string->bytes/utf-8 "wrong-secret"))
             (eval:result "" "" "CryptUnprotectData failed: ERROR_INVALID_DATA: The data is invalid or corrupted"))
  (eval:alts (import-protected-bytes (file->bytes "token.encrypted"))
             (eval:result "" "" "CryptUnprotectData failed: ERROR_INVALID_DATA: The data is invalid or corrupted"))
]

@section{Complete Example: Storing Configuration}

Here is a complete example for storing encrypted configuration. The configuration is serialized to
JSON, protected, exported to a file, and the in-memory copy is destroyed:

@examples[#:eval ev #:label #f
  (eval:alts (require json) (void))
  (eval:alts (define config
               (hasheq 'database-password "super-secret"
                       'api-key "key-12345"))
             (void))
  (eval:alts (define config-pv
               (make-protected-value (string->bytes/utf-8 (jsexpr->string config))))
             (void))
  (eval:alts (display-to-file (export-protected-bytes config-pv
                                                      #:description "App Configuration"
                                                      #:entropy (string->bytes/utf-8 "app-v1-secret"))
                              "config.encrypted"
                              #:exists 'replace)
             (void))
  (eval:alts (destroy-protected-value! config-pv) (void))
]

Later, the file is imported and the configuration is parsed inside the callback:

@examples[#:eval ev #:label #f
  (eval:alts (define loaded-config-pv
               (import-protected-bytes (file->bytes "config.encrypted")
                                       #:entropy (string->bytes/utf-8 "app-v1-secret")))
             (void))
  (eval:alts (protected-value-description loaded-config-pv)
             (eval:result @racketresult["App Configuration"]))
  (eval:alts (with-decrypted-data loaded-config-pv
               (lambda (config-bytes)
                 (string->jsexpr (bytes->string/utf-8 config-bytes))))
             (eval:result @racketresultfont{@literal{'#hasheq((api-key . "key-12345") (database-password . "super-secret"))}}))
]
