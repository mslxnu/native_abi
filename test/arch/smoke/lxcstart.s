.text
.global _start
_start:
    bl main
    mov x8, #93
    svc #0
