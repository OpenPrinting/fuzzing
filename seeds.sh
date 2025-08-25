mkdir -p /home/mdimado/Desktop/gsoc/fuzzing/projects/pycups/seeds/fuzz_print_job

cd /home/mdimado/Desktop/gsoc/fuzzing/projects/pycups/seeds/fuzz_print_job

# Basic print jobs
echo -ne "HP_Printer\x00/tmp/test.pdf\x00Test Job\x00copies\x001" > basic_job.bin
echo -ne "Network_Printer\x00document.ps\x00Important Document\x00sides\x00two-sided-long-edge" > duplex_job.bin

# Edge cases
echo -ne "café-printer\x00tëst.pdf\x00Tést Jöb\x00págés\x001-3" > utf8_job.bin
echo -ne "\x00\x00\x00\x00\x00" > empty_job.bin

# Path traversal attempts  
echo -ne "printer\x00../../../etc/passwd\x00Evil Job\x00output\x00/dev/null" > path_traversal.bin

# Many options
echo -ne "printer\x00file.pdf\x00job\x00opt1\x00val1\x00opt2\x00val2\x00opt3\x00val3" > many_options.bin