set interactive-mode off
catch syscall set_thread_area
break tester_main
run
printf "gs_base<32> := %#x\n", *($ebx + 4)
continue
continue
generate-core-file rsa_keygen_wolfssl-O2_32.core
kill
quit
