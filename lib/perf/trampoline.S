    .text
    .global      _perf_trampoline_func_start
    .align 16
_perf_trampoline_func_start:
#ifdef __x86_64__
    push    %rbp
    mov     _perf_trampoline_target_address(%rip), %r11
    call    *%r11
    pop	    %rbp
    ret
    .align 8
_perf_trampoline_target_address:
    .quad 0x0
#endif // __x86_64__

    .global      _perf_trampoline_func_end
_perf_trampoline_func_end:
    .section .note.GNU-stack,"",@progbits
