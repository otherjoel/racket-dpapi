#lang racket/base

(require racket/runtime-path
         scribble/core
         scribble/decode
         scribble/manual
         scribble/example
         scribble/html-properties)

(provide inline-note
         terminal
         :>)

(define-runtime-path doc-css "doc-util.css")

;; An inline note/aside for tips, warnings, or supplementary info
;; Use #:type 'note (default), 'tip, or 'warning
(define (inline-note #:type [type 'note] . elems)
  (compound-paragraph
   (style "inline-note"
          (list (css-style-addition doc-css)
                (attributes `((class . ,(format "refcontent ~a" type))))
                (alt-tag "aside")))
   (decode-flow elems)))

;; Style for sample terminal output
(define (terminal . args)
  (compound-paragraph (style "terminal" (list (color-property (list #x66 #x33 #x99))
                                              (css-style-addition doc-css)
                                              (alt-tag "div")))
                      (list (apply verbatim args))))

;; Simulate a command-line prompt. Any prompt symbols/separators are handled in CSS.
(define (:> . elems)
  (element (style "prompt" (list (color-property (list 0 0 0))))
           (apply exec elems)))