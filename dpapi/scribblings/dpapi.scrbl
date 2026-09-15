#lang scribble/manual
@require[@for-label[dpapi
                    racket/base
                    racket/contract]
         "doc-util.rkt"]

@title[#:style 'toc]{DPAPI: Windows Data Protection API for Racket}
@author{Joel Dueck}

@defmodule[dpapi]

This library provides a Racket interface to the Windows Data Protection API (DPAPI), enabling secure
encryption of sensitive data using Windows credentials.

The @hyperlink["https://learn.microsoft.com/en-us/windows/win32/api/dpapi/"]{Windows Data Protection
API (DPAPI)} is a cryptographic service provided by Windows that allows applications to encrypt data
using keys derived from user or machine credentials. This eliminates the need to manage encryption
keys explicitly, as Windows handles key generation, storage, and protection automatically.

Requires Windows Vista or later and Racket 8.0 or later. This library has been tested on
Windows 11 / x86_64. Source is available 
@hyperlink["https://github.com/otherjoel/racket-dpapi"]{on GitHub.}

@inline-note{If you use this library in your software, @hyperlink["mailto:joel@jdueck.net"]{email
me} to introduce yourself. This is the sole condition of the project's
@hyperlink["https://github.com/otherjoel/racket-dpapi/blob/main/LICENSE.md"]{permissive
license.} (See @hyperlink["https://joeldueck.com/how-i-license.html"]{How I License} for
background.)}

@local-table-of-contents[]

@include-section["getting-started.scrbl"]
@include-section["reference.scrbl"]
@include-section["security-best-practices.scrbl"]
