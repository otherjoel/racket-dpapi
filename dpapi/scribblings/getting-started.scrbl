#lang scribble/manual

@require[@for-label[dpapi
                    racket/base]]

@require["doc-util.rkt"]

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
The only way to access the plaintext is through a callback inside @racket[with-decrypted-data]:

@racketblock[
(require dpapi)

(code:comment2 "Check if DPAPI is available")
(unless (dpapi-available?)
  (error "DPAPI not available on this platform"))

(code:comment2 "Create a protected value - an encrypted copy of the data")
(define password
  (make-protected-value (string->bytes/utf-8 "my-secret-password")))

(code:comment2 "Access the data through a callback")
(with-decrypted-data password
  (lambda (pwd-bytes)
    (define pwd (bytes->string/utf-8 pwd-bytes))
    (connect-to-database pwd)))
(code:comment "Password is automatically re-encrypted after the callback")

(code:comment "When done, zero out memory")
(destroy-protected-value! password)
]

The @racket[with-decrypted-data] pattern ensures that data remains unencrypted only during the time
it is needed. The data gets re-encrypted automatically once the callback is complete, even if the
callback throws an exception.

Note that @racket[make-protected-value] encrypts a @emph{copy} of the bytes you pass in. The
original byte string is left untouched, so in the example above the plaintext password also
remains in memory until it is garbage collected. See @secref["security-best-practices"] for how to
zero it yourself.

@section{Saving and Loading Encrypted Data}

A @tech{protected value} is not suitable for writing to permanent storage, because it is generally
scoped only to the currently running process.

The @racket[export-protected-bytes] and @racket[import-protected-bytes] functions convert between
in-memory protected values and DPAPI-encrypted values that can be used across sessions, without
exposing the plaintext to the rest of your code:

@racketblock[
(require dpapi)

(code:comment2 "Create a protected value")
(define token
  (make-protected-value (string->bytes/utf-8 token-from-oauth)))

(code:comment2 "Export to DPAPI-encrypted bytes and save to disk")
(define encrypted-bytes
  (export-protected-bytes token
                          #:entropy (string->bytes/utf-8 "app-v1-secret")
                          #:description "OAuth Token"))

(with-output-to-file "token.encrypted"
  (lambda () (write-bytes encrypted-bytes))
  #:exists 'replace)

(code:comment2 "--- Later: load from disk ---")

(define loaded-token
  (import-protected-bytes (file->bytes "token.encrypted")
                          #:entropy (string->bytes/utf-8 "app-v1-secret")))

(code:comment2 "Use the token through a callback")
(with-decrypted-data loaded-token
  (lambda (token-bytes)
    (make-api-request (bytes->string/utf-8 token-bytes))))
]

To retrieve the description stored with the encrypted data:

@racketblock[
(define loaded-token
  (import-protected-bytes (file->bytes "token.encrypted")
                          #:entropy (string->bytes/utf-8 "app-v1-secret")))

(protected-value-description loaded-token)
(code:comment2 "=> \"OAuth Token\"")
]

@subsection{Entropy}

The optional @racket[#:entropy] parameter on @racket[export-protected-bytes] and
@racket[import-protected-bytes] adds a secondary secret. Without the correct entropy,
decryption will fail even for the same Windows user. The same entropy must be provided
for both export and import.

@racketblock[
(code:comment "Export with entropy")
(define encrypted
  (export-protected-bytes pv
                          #:entropy (string->bytes/utf-8 "my-app-secret")))

(code:comment2 "Import must use the same entropy")
(define pv2
  (import-protected-bytes encrypted
                          #:entropy (string->bytes/utf-8 "my-app-secret")))

(code:comment2 "Wrong entropy will raise exn:fail:dpapi")
]

@section{Complete Example: Storing Configuration}

Here's a complete example for storing encrypted configuration:

@racketblock[
(require dpapi json)

(code:comment2 "Configuration to encrypt")
(define config
  (hasheq 'database-password "super-secret"
          'api-key "key-12345"))

(code:comment2 "Serialize, protect, and export")
(define config-json (jsexpr->string config))
(define config-pv
  (make-protected-value (string->bytes/utf-8 config-json)))

(define encrypted-config
  (export-protected-bytes config-pv
                          #:description "App Configuration"
                          #:entropy (string->bytes/utf-8 "app-v1-secret")))

(code:comment2 "Save to file")
(with-output-to-file "config.encrypted"
  (lambda () (write-bytes encrypted-config))
  #:exists 'replace)

(destroy-protected-value! config-pv)

(code:comment2 "--- Later: Load and use ---")

(code:comment2 "Import from file")
(define loaded-config-pv
  (import-protected-bytes (file->bytes "config.encrypted")
                          #:entropy (string->bytes/utf-8 "app-v1-secret")))

(code:comment2 "Use the config through a callback")
(with-decrypted-data loaded-config-pv
  (lambda (config-bytes)
    (define loaded-config
      (string->jsexpr (bytes->string/utf-8 config-bytes)))
    (displayln loaded-config)))
(code:comment "=> '#hasheq((database-password . \"super-secret\") (api-key . \"key-12345\"))")
]
