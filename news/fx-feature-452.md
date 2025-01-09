`unset_empties()`: change the default for ignorecase to FALSE, remove utf8
support.  UTF8 validation and case folding is expensive and most use-cases
do not really need that. If there's a specific use-case, an explicit utf8
flag can be added back.
