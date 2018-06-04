" Vim syntax file
" Language:		NiceShaper configuration files (/etc/niceshaper/*.conf)
" Maintainer:	Mariusz Jedwabny <mariusz@jedwabny.net>
" License:		This file is subject to the terms and conditions of the 
"			GNU General Public License. See the file COPYING in the 
"			main directory of this archive for more details.
" Last Change: 2014-04-03
" URL: http://niceshaper.jedwabny.net
if exists("b:current_syntax")
 finish
endif

" Syntax clusters
syn cluster nsType1List contains=nsValue,nsBoolean,nsComment,nsLoopMacroSymbol 
syn cluster nsType4List contains=nsParameter,@nsType1List

" Comments
syn region nsComment start=/#/ end=/$/
syn region nsComment start=/<#/ end=/#>/

" Booleans
syn keyword nsBoolean contained yes no

" Sections
syn match nsSection /^\s*<[a-zA-Z0-9_\-.]\+>\s*$/
syn match nsSection /^\s*<\/[a-zA-Z0-9_\-.]\+>\s*$/
syn match nsSection /^\s*<\/>\s*$/

" Macros
syn match nsLoopMacroSymbol contained /\$/
syn match nsLoopMacroSymbol contained /%/
syn region nsLoopMacroRegion matchgroup=nsLoopMacro start=/^\s*{[a-zA-Z0-9_\-., ]\+}\s*$/ end=/^\s*{\/}\s*$/ contains=nsDirectiveRegion,nsComment,nsLoopMacroSymbol

" NiceShaper directives
" Directives with format: directive value
syn match nsValue contained "pl"
syn match nsValue contained "en"
syn match nsValue contained "download"
syn match nsValue contained "upload"
syn match nsValue contained "PREROUTING"
syn match nsValue contained "POSTROUTING"
syn match nsValue contained "ACCEPT"
syn match nsValue contained "RETURN"
syn region nsDirectiveRegion matchgroup=nsDirective start=/^\s*\(ceil\|hold\|lang\|low\|mode\|rate\|reload\|set-mark\|strict\)\s\+/ end=/$/ contains=@nsType1List keepend

" Directives with format: directive value [value]
syn keyword nsValue contained iptables
syn region nsDirectiveRegion matchgroup=nsDirective start=/^\s*\(debug\|fallback\|local-subnets\|mark-on-ifaces\|run\)\s\+/ end=/$/ contains=@nsType1List keepend

" Directives with format: directive parameter value [parameter value]
syn match nsParameter contained "file-owner"
syn match nsParameter contained "file-group"
syn match nsParameter contained "file-mode"
syn match nsParameter contained "file-rewrite"
syn keyword nsParameter contained file syslog terminal
syn keyword nsParameter contained unit classes sum file owner group mode rewrite
syn keyword nsParameter contained address password
syn keyword nsParameter contained shape speed
syn keyword nsParameter contained scheduler prio burst cburst
syn keyword nsParameter contained hash perturb
syn keyword nsParameter contained autoredirect
syn keyword nsParameter contained low ceil rate day week month file
syn match nsParameter contained "do-not-shape"
syn match nsParameter contained "htb-burst"
syn match nsParameter contained "htb-cburst"
syn match nsParameter contained "download-hook"
syn match nsParameter contained "upload-hook"
syn match nsParameter contained "target"
syn match nsParameter contained "imq-autoredirect"
syn match nsParameter contained "time-period"
syn match nsParameter contained "reset-hour"
syn match nsParameter contained "reset-wday"
syn match nsParameter contained "reset-mday"
syn match nsParameter contained "do-not-shape-method"
syn match nsParameter contained "unclassified-method"
syn match nsParameter contained "fallback-rate"
syn keyword nsValue contained safe
syn match nsValue contained "full-throttle"
syn match nsValue contained "fallback-class"
syn match nsValue contained "do-not-control"
syn region nsDirectiveRegion matchgroup=nsDirective start=/^\s*\(log\|users\|status\|stats\|listen\|section\|htb\|sfq\|esfq\|iptables\|alter\|quota\|iface-[a-z0-9+.:\-]\+\|auto-hosts\)\s\+/ end=/$/ contains=@nsType4List keepend

" Directives 'host' and 'class-*'
syn region nsDirectiveRegion matchgroup=nsDirective start=/^\s*\(host\|class\|class-virtual\|class-wrapper\|class-do-not-shape\)\s\+/ end=/$/ contains=nsComment,nsLoopMacroSymbol keepend

" Directives 'match' and 'include'
syn keyword nsParameter contained proto srcip dstip sport srcport dport dstport
syn keyword nsParameter contained file
syn match nsParameter contained "in-iface"
syn match nsParameter contained "out-iface"
syn match nsParameter contained "from-local"
syn match nsParameter contained "to-local"
syn match nsParameter contained "not-srcip"
syn match nsParameter contained "not-dstip"
syn match nsParameter contained "not-srcport"
syn match nsParameter contained "not-sport"
syn match nsParameter contained "not-dstport"
syn match nsParameter contained "not-dport"
syn match nsParameter contained "ttl-lower"
syn match nsParameter contained "ttl-greater"
syn match nsParameter contained "set-mark"
syn keyword nsValue contained new established related invalid untracked
syn keyword nsParameter contained length state tos ttl mark
syn region nsDirectiveRegion matchgroup=nsDirective start=/^\s*\(match\|include\)\s\+/ end=/$/ contains=@nsType4List keepend

" Default highlighting
hi def link	nsComment Comment
hi def link	nsBoolean Function
hi def link	nsSection Label
hi def link	nsLoopMacro Label
hi def link	nsLoopMacroSymbol Label
hi def link nsDirective Number
hi def link	nsParameter Type
hi def link nsValue Function

let b:current_syntax = "niceshaper"

