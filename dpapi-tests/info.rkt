#lang info
(define collection "dpapi")
(define deps '("dpapi-lib"
               "rackunit-lib"
               "base"))
(define build-deps '("rackunit-lib" "dpapi-lib"))
(define pkg-desc "Tests for DPAPI library")
(define version "1.0")
(define pkg-authors '("Joel Dueck"))
(define license 'LicenseRef-CreatorCxn-1.0)
