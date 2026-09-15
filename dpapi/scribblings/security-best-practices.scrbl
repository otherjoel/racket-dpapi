#lang scribble/manual
@require[@for-label[dpapi
                    racket/base]]

@title[#:tag "security-best-practices"]{Security Best Practices}

@section{Understanding the Threat Model}

DPAPI encrypts data using credentials tied to a Windows user account (or machine). To use it
well, you need to understand which threats it addresses and which it does not.

@subsection{What DPAPI Protects Against}

DPAPI is designed to protect @bold{data at rest}. It is effective against:

@itemlist[
  @item{@bold{Stolen files}: An attacker who copies encrypted files off the machine cannot
        decrypt them without the user's Windows credentials.}
  @item{@bold{Other users on the same machine}: With user-scope encryption (the default),
        other users on the machine cannot decrypt your data.}
  @item{@bold{Offline disk access}: An attacker who removes the hard drive or reads a disk
        image cannot decrypt data without the user's credentials.}
]

In short, DPAPI is useful whenever sensitive data needs to be stored on disk and you
want it tied to a specific user's login session.

@subsection{What DPAPI Does Not Protect Against}

@itemlist[
  @item{@bold{Malware running as your user}: Any process running with your privileges can
        call the same DPAPI functions and decrypt your data.}
  @item{@bold{A compromised user account}: If an attacker obtains your Windows credentials,
        they can decrypt anything protected under your account.}
  @item{@bold{Memory inspection of a running process}: While your program is running,
        decrypted data will be present in process memory. Debuggers, memory dump tools,
        and other processes with sufficient privileges can read it. This is true regardless
        of how carefully you manage data lifetimes in your code---Racket's garbage collector
        may copy data between memory locations at any time, and there is no reliable way to
        ensure all copies are zeroed.}
  @item{@bold{Physical memory attacks}: Cold boot attacks, DMA attacks, and similar
        techniques can read data from RAM.}
]

@bold{The key takeaway}: DPAPI protects data at rest on disk. It does not provide meaningful
protection against an attacker who can inspect the memory of your running process. Do not
rely on careful coding patterns to prevent in-memory exposure---instead, understand that
decrypted data @emph{will} be visible in memory while your program runs, and evaluate whether
that is acceptable for your threat model.

@section{Practical Guidance}

The risks that matter most in practice are the ones that turn temporary in-memory exposure
into @bold{persistent, recoverable leaks}---places where secrets end up written to disk or
transmitted somewhere they shouldn't be.

@itemlist[
 
 @item{Never serialize decrypted data using @racket[write], @racket[print], @racket[display],
  @racket[format] or related operations. If there is an output port involved, sensitive data should
be kept well away. }
                                         
@item{Never use decrypted data in logging or in raised exceptions.}

@item{Avoid binding decrypted data to any variables in general, and never bind decrypted data to
  variables that persist outside the scope of the place where it is actually needed.}

@item{@racket[make-protected-value] copies its input and cannot zero the original, which may be
  immutable. When you create a secret yourself, build it in a mutable byte string and zero it with
  @racket[bytes-fill!] as soon as the @tech{protected value} exists:

  @racketblock[
  (define secret (string->bytes/utf-8 (read-line)))
  (define pv (make-protected-value secret))
  (bytes-fill! secret 0)
  ]

  This does not remove every trace (the string returned by @racket[read-line] above is still in
  memory, for instance), but it removes the copy you control.}

@item{Although in-memory protection has hard limits (see above), it is still good practice to
encrypt data early and decrypt it late. This reduces the window during which plaintext
is present in memory, and---more importantly---reduces the chance of accidentally passing
it to code that logs, serializes, or otherwise persists it.
 
 The @tech{protected value} API and @racket[with-decrypted-data] callback pattern
enforce this discipline at the API level. Their purpose is not to guarantee that
decrypted data is absent from process memory---as discussed above, that is not a
realistic goal---but to limit the @emph{visibility} of decrypted data to running
Racket code. Because the only way to access the plaintext is through the
@racket[with-decrypted-data] callback, it becomes structurally difficult for other
parts of your program to accidentally use, log, or persist the decrypted value.}
 
 ]

@section{Entropy Management}

The optional @racket[#:entropy] parameter adds a secondary secret that must be
provided at both encryption and decryption time. This means an attacker needs both the
user's Windows credentials @emph{and} the entropy value to decrypt the data.

However, the entropy itself must be stored somewhere, which creates a bootstrapping
problem. Common approaches, each with tradeoffs:

@itemlist[
  @item{@bold{Hardcoded in source code}: Simple, but visible to anyone with source access.
        Acceptable for open-source applications where data is per-user anyway.}
  @item{@bold{Environment variable}: Slightly better than hardcoding, but environment
        variables can be exposed via process listings or crash dumps.}
  @item{@bold{Restricted configuration file}: Effective if file permissions are set
        correctly. Remember that the file could still be copied by a privileged user.}
  @item{@bold{User-provided passphrase}: Most secure, but requires the user to
        remember it. Use a proper key derivation function (PBKDF2, Argon2) to convert
        the passphrase to entropy bytes.}
  @item{@bold{No entropy}: Rely solely on Windows user credentials. Simpler, but
        provides no protection against other applications running as the same user.}
]

Choose based on your threat model. For most applications that simply need to store
tokens or credentials on behalf of a user, hardcoded or no entropy is often sufficient
---the primary value of DPAPI in that case is protecting the data at rest on disk.
