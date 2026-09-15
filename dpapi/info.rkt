#lang info
(define collection "dpapi")
(define deps '("base" "dpapi-lib"))
(define implies '("dpapi-lib"))
(define build-deps '("dpapi-lib"
                     "scribble-lib" "racket-doc" "rackunit-lib"))
(define scribblings '(("scribblings/dpapi.scrbl" (multi-page))))
(define pkg-desc "Documentation for DPAPI")
(define version "1.0")
(define pkg-authors '("Joel Dueck"))
(define license 'LicenseRef-CreatorCxn-1.0)
